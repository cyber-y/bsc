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
// Header.Number, on the NORMAL miner block-production path. NOT for production.
// Hard-disabled on mainnet/chapel regardless of any switch.
//
// Two attack modes (env MALICIOUS_BIG_NUMBER_MODE):
//
//	add64  (default) -- in Prepare, header.Number += 2^64. Uint64() is
//	                    preserved (== real height H), the big.Int is >64-bit.
//	                    Reaches verifyCascadingFields' post-genesis checks; a
//	                    parent-continuity diff check (header.Number-parent==1
//	                    in big.Int) CATCHES this.
//
//	zero64          -- in Seal, right before signing, header.Number = H << 64.
//	                    The low 64 bits are ZERO, so Uint64() == 0. This slips
//	                    the `if number == 0 { return nil }` genesis short-circuit
//	                    at the TOP of verifyCascadingFields, so any parent-
//	                    continuity check placed AFTER that short-circuit is
//	                    UNREACHABLE for this block -- i.e. it escapes that fix.
//	                    (On the full sync path verifySeal's own number==0 guard
//	                    still rejects with errUnknownBlock; the truly uncovered
//	                    path is a standalone VerifyUnsealedHeader with no
//	                    verifySeal, e.g. MEV BidBlock admission. A proper fix is
//	                    an early !Number.IsUint64() reject before any Uint64().)
//
// Injection happens BEFORE the seal signature is produced, so the signature is
// valid for the malformed header (a validly-signed malformed block, not a
// post-seal tamper that verifySeal's ecrecover would catch).
//
// zero64 injection point is INSIDE Seal (not Prepare): Seal's top guard
// `header.Number.Uint64() == 0 -> errUnknownBlock`, its snapshot(number-1)
// lookup, delay and vote-attestation all run first on the REAL height H; only
// the final signed header carries H<<64. Injecting H<<64 back in Prepare would
// make the byzantine node fail to seal its own block.
//
// Scope: mounted only on the local miner path (Prepare + Seal). The MEV
// BidBlock path (PrepareForBidBlock) is not injected.

const (
	// injectBigBlockNumberEnv is the master switch. Inverted, default-ON
	// semantics: injection is ON unless this env var is exactly "2".
	//   unset / "" / "1" / anything-but-"2" -> ENABLED (default)
	//   "2"                                  -> DISABLED
	injectBigBlockNumberEnv = "MALICIOUS_BIG_NUMBER"
	injectDisableValue      = "2"

	// injectModeEnv selects the attack shape.
	injectModeEnv    = "MALICIOUS_BIG_NUMBER_MODE"
	injectModeAdd64  = "add64"  // default: Prepare, Number += 2^64 (Uint64()==H)
	injectModeZero64 = "zero64" // Seal, Number = H<<64 (Uint64()==0)
)

// injectionBuildTag is a build/version marker printed once at engine
// construction and once on the first Prepare, so operators can confirm from the
// logs that the RUNNING BINARY carries this code (guards against the stale-
// binary trap). Bump it whenever the injection behavior changes.
const injectionBuildTag = "big-number-injection/v3 (default-ON, disable=2, modes=add64|zero64)"

var (
	twoPow64    = new(big.Int).Lsh(big.NewInt(1), 64)
	bannerOnce  sync.Once
	prepareOnce sync.Once
)

// isProtectedChain reports whether injection must never happen (BSC mainnet 56
// / Chapel testnet 97), regardless of the env switch.
func (p *Parlia) isProtectedChain() bool {
	if p.chainConfig == nil || p.chainConfig.ChainID == nil {
		return false
	}
	return p.chainConfig.ChainID.Cmp(params.BSCChainConfig.ChainID) == 0 ||
		p.chainConfig.ChainID.Cmp(params.ChapelChainConfig.ChainID) == 0
}

// injectionEnabled resolves the on/off decision and the env value behind it.
func (p *Parlia) injectionEnabled() (enabled bool, envValue string) {
	envValue = os.Getenv(injectBigBlockNumberEnv)
	if p.isProtectedChain() {
		return false, envValue
	}
	return envValue != injectDisableValue, envValue // default ON
}

// injectionMode returns the selected attack mode (default add64).
func (p *Parlia) injectionMode() string {
	if os.Getenv(injectModeEnv) == injectModeZero64 {
		return injectModeZero64
	}
	return injectModeAdd64
}

// logInjectionBanner prints the one-time build/version+mode banner from New().
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
			"mode", p.injectionMode(),
			"resolvedMode", modeString(enabled),
			"disableWith", injectBigBlockNumberEnv+"="+injectDisableValue,
		)
	})
}

func modeString(enabled bool) string {
	if enabled {
		return "ENABLED"
	}
	return "DISABLED (header untouched)"
}

// maybeInjectBigBlockNumber is the Prepare hook. It performs the add64 attack
// (Number += 2^64). In zero64 mode it is a no-op here (injection deferred to
// Seal). Must run before FinalizeAndAssemble/Seal so the seal covers the value.
func (p *Parlia) maybeInjectBigBlockNumber(header *types.Header) {
	enabled, envValue := p.injectionEnabled()
	mode := p.injectionMode()

	prepareOnce.Do(func() {
		log.Warn("BIG_NUMBER_INJECTION first Prepare reached (miner path is live)",
			"buildTag", injectionBuildTag,
			"resolvedMode", modeString(enabled),
			"mode", mode,
			"envValue", envValue,
		)
	})

	if p.isProtectedChain() {
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
	if mode != injectModeAdd64 {
		// zero64 injects in Seal, not here.
		log.Info("BIG_NUMBER_INJECTION[add64] skipped in Prepare: mode is not add64",
			"mode", mode, "number", headerNumberString(header))
		return
	}
	if header.Number == nil {
		log.Warn("BIG_NUMBER_INJECTION[add64] skipped: header.Number is nil")
		return
	}

	origUint64 := header.Number.Uint64()
	header.Number = new(big.Int).Add(header.Number, twoPow64)

	log.Warn("BIG_NUMBER_INJECTION[add64] active: inflated header.Number by 2^64 (Uint64() preserved)",
		"buildTag", injectionBuildTag,
		"expectedHeight", origUint64,
		"truncatedUint64", header.Number.Uint64(),
		"bitlen", header.Number.BitLen(),
		"bigNumber", header.Number.String(),
		"parentHash", header.ParentHash,
		"coinbase", header.Coinbase,
	)
}

// maybeInjectSealBlockNumber is the Seal hook for the zero64 attack. It must be
// called inside Seal, AFTER the top-of-Seal number==0 guard / snapshot / delay
// (which run on the real height H) and IMMEDIATELY BEFORE the seal signature is
// computed, so the signature covers the malformed Number.
//
// It sets header.Number = H << 64: the low 64 bits become zero (Uint64() == 0),
// so the block slips verifyCascadingFields' genesis short-circuit; the high
// bits keep H so blocks at different heights stay distinct.
func (p *Parlia) maybeInjectSealBlockNumber(header *types.Header) {
	enabled, envValue := p.injectionEnabled()
	if !enabled || p.injectionMode() != injectModeZero64 || header.Number == nil {
		return
	}
	// H must be > 0 here (Seal's top guard already rejected number==0).
	origHeight := new(big.Int).Set(header.Number)
	header.Number = new(big.Int).Lsh(origHeight, 64) // H << 64 -> low 64 bits = 0

	log.Warn("BIG_NUMBER_INJECTION[zero64] active: forced header.Number low 64 bits to zero (Uint64()==0)",
		"buildTag", injectionBuildTag,
		"realHeight", origHeight.String(),
		"truncatedUint64", header.Number.Uint64(), // == 0
		"isUint64", header.Number.IsUint64(),       // == false
		"bitlen", header.Number.BitLen(),
		"bigNumber", header.Number.String(),
		"parentHash", header.ParentHash,
		"coinbase", header.Coinbase,
		"envValue", envValue,
	)
}

func headerNumberString(header *types.Header) string {
	if header == nil || header.Number == nil {
		return "<nil>"
	}
	return header.Number.String()
}
