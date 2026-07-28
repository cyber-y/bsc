package parlia

import (
	"math/big"
	"os"
	"sync"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

// Fault injection for the big.Int -> uint64 truncation weakness around
// Header.Number, exercised on the NORMAL miner block-production path only
// (Prepare). NOT for production. Hard-disabled on mainnet/chapel regardless
// of any switch.
//
// A byzantine validator, exactly at block-production time (Prepare, before
// FinalizeAndAssemble/Seal run), inflates header.Number by exactly 2^64 so
// that header.Number.Uint64() still equals the expected height (the low 64
// bits are unchanged -- adding 2^64 never touches them), but the big.Int
// itself is oversized (BitLen > 64, fails Header.SanityCheck's IsUint64()).
//
// Because this happens BEFORE the seal signature is produced, the signature
// is computed over, and is valid for, this inflated header -- unlike
// tampering the header after sealing (which invalidates the signature and
// gets caught by verifySeal's ecrecover mismatch instead of by any
// number-shape check).
//
// Scope note: this hook is intentionally mounted ONLY on Prepare (the local
// miner path). The MEV BidBlock path (PrepareForBidBlock) is not injected.

// injectBigBlockNumberEnv controls the injection. NOTE the inverted, default-ON
// semantics: injection is ON unless this env var is exactly "2".
//
//	unset / "" / "1" / anything-but-"2"  -> injection ENABLED (default)
//	"2"                                  -> injection DISABLED
const injectBigBlockNumberEnv = "MALICIOUS_BIG_NUMBER"

// injectDisableValue is the single env value that turns the injection OFF.
const injectDisableValue = "2"

// injectionBuildTag is a build/version marker. It is printed once at engine
// construction and once on the first Prepare so operators can confirm from the
// logs that the RUNNING BINARY actually contains this fault-injection code
// (guards against the "stale binary / not redeployed" trap). Bump it whenever
// the injection behavior changes.
const injectionBuildTag = "big-number-injection/v2 (default-ON, disable=MALICIOUS_BIG_NUMBER=2)"

var (
	twoPow64    = new(big.Int).Lsh(big.NewInt(1), 64)
	bannerOnce  sync.Once
	prepareOnce sync.Once
)

// isProtectedChain reports whether the chain is one where injection must never
// happen (BSC mainnet 56 / Chapel testnet 97), regardless of the env switch.
func (p *Parlia) isProtectedChain() bool {
	if p.chainConfig == nil || p.chainConfig.ChainID == nil {
		return false
	}
	return p.chainConfig.ChainID.Cmp(params.BSCChainConfig.ChainID) == 0 ||
		p.chainConfig.ChainID.Cmp(params.ChapelChainConfig.ChainID) == 0
}

// injectionEnabled resolves the current on/off decision and the env value that
// produced it (returned for logging).
func (p *Parlia) injectionEnabled() (enabled bool, envValue string) {
	envValue = os.Getenv(injectBigBlockNumberEnv)
	if p.isProtectedChain() {
		return false, envValue
	}
	// Default ON: disabled only when explicitly set to "2".
	return envValue != injectDisableValue, envValue
}

// logInjectionBanner prints the one-time build/version banner. Called from
// New() (fires on every node, right after logging is configured) so operators
// can confirm the running binary carries this code and see the resolved mode.
func (p *Parlia) logInjectionBanner() {
	bannerOnce.Do(func() {
		enabled, envValue := p.injectionEnabled()
		var chainID *big.Int
		if p.chainConfig != nil {
			chainID = p.chainConfig.ChainID
		}
		log.Warn("BIG_NUMBER_INJECTION build loaded (QA fault injection, NOT for production)",
			"buildTag", injectionBuildTag,
			"chainID", chainID,
			"protectedChain", p.isProtectedChain(),
			"envVar", injectBigBlockNumberEnv,
			"envValue", envValue,
			"resolvedMode", modeString(enabled),
			"disableWith", injectBigBlockNumberEnv+"="+injectDisableValue,
		)
	})
}

func modeString(enabled bool) string {
	if enabled {
		return "ENABLED (will inflate header.Number by 2^64)"
	}
	return "DISABLED (header untouched)"
}

// maybeInjectBigBlockNumber inflates header.Number by 2^64 in place when the
// injection is enabled. Must be called from Prepare, before
// FinalizeAndAssemble/Seal compute the seal signature, so the signature
// remains valid for the inflated value.
func (p *Parlia) maybeInjectBigBlockNumber(header *types.Header) {
	enabled, envValue := p.injectionEnabled()

	// One-time confirmation, the first time the miner path actually reaches
	// this hook: proves both "correct binary" and "block-production path hit".
	prepareOnce.Do(func() {
		log.Warn("BIG_NUMBER_INJECTION first Prepare reached (miner path is live)",
			"buildTag", injectionBuildTag,
			"resolvedMode", modeString(enabled),
			"envValue", envValue,
		)
	})

	if p.isProtectedChain() {
		// Should never happen on a QA devnet; log loudly if it does.
		log.Warn("BIG_NUMBER_INJECTION skipped: protected chain (mainnet/chapel), env ignored",
			"chainID", p.chainConfig.ChainID)
		return
	}
	if !enabled {
		log.Info("BIG_NUMBER_INJECTION skipped: disabled by env",
			"envVar", injectBigBlockNumberEnv, "envValue", envValue,
			"number", headerNumberString(header))
		return
	}
	if header.Number == nil {
		log.Warn("BIG_NUMBER_INJECTION skipped: header.Number is nil")
		return
	}

	origUint64 := header.Number.Uint64()
	header.Number = new(big.Int).Add(header.Number, twoPow64)

	log.Warn("BIG_NUMBER_INJECTION active: inflated header.Number beyond uint64",
		"buildTag", injectionBuildTag,
		"expectedHeight", origUint64,
		"truncatedUint64", header.Number.Uint64(),
		"bitlen", header.Number.BitLen(),
		"bigNumber", header.Number.String(),
		"parentHash", header.ParentHash,
		"coinbase", header.Coinbase,
	)
}

func headerNumberString(header *types.Header) string {
	if header == nil || header.Number == nil {
		return "<nil>"
	}
	return header.Number.String()
}
