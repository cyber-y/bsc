package parlia

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

// newInjectionParlia builds a bare Parlia carrying only the chain config the
// injection hook inspects. maybeInjectBigBlockNumber touches nothing else.
func newInjectionParlia(chainID int64) *Parlia {
	cfg := &params.ChainConfig{ChainID: big.NewInt(chainID)}
	return &Parlia{chainConfig: cfg}
}

// devnetChainID is any chain that is neither BSC mainnet (56) nor Chapel (97),
// so the hard safety guard does not short-circuit the hook.
const devnetChainID = 714

// TestInjectionDefaultsToZero64OnDefault verifies the defaults: with both env
// vars unset, injection is ON and the mode is zero64 -> the Seal hook fires
// (Uint64()==0) and the Prepare hook is a no-op.
func TestInjectionDefaultsToZero64OnDefault(t *testing.T) {
	// No t.Setenv at all -> MALICIOUS_BIG_NUMBER unset (ON) and
	// MALICIOUS_BIG_NUMBER_MODE unset (zero64).
	p := newInjectionParlia(devnetChainID)
	if mode := p.injectionMode(); mode != injectModeZero64 {
		t.Fatalf("default mode should be zero64, got %q", mode)
	}
	const height = 12345

	// Prepare hook is a no-op in the default (zero64) mode.
	ph := &types.Header{Number: big.NewInt(height)}
	p.maybeInjectBigBlockNumber(ph)
	if ph.Number.Cmp(big.NewInt(height)) != 0 {
		t.Fatalf("default zero64: Prepare hook must be no-op, got %s", ph.Number)
	}

	// Seal hook fires by default: Number = H<<64, Uint64()==0.
	sh := &types.Header{Number: big.NewInt(height)}
	p.maybeInjectSealBlockNumber(sh)
	if got := sh.Number.Uint64(); got != 0 {
		t.Fatalf("default zero64: Seal hook should force Uint64()==0, got %d", got)
	}
	if sh.Number.IsUint64() {
		t.Fatalf("default zero64: Number should be >64-bit after Seal hook")
	}
}

// TestMaybeInjectBigBlockNumberDisabledByValue2 verifies the only off switch:
// MALICIOUS_BIG_NUMBER=2 leaves the header untouched.
func TestMaybeInjectBigBlockNumberDisabledByValue2(t *testing.T) {
	t.Setenv(injectBigBlockNumberEnv, injectDisableValue) // "2"
	p := newInjectionParlia(devnetChainID)
	const height = 12345
	header := &types.Header{Number: big.NewInt(height)}

	p.maybeInjectBigBlockNumber(header)

	if header.Number.Cmp(big.NewInt(height)) != 0 {
		t.Fatalf("value=2 should disable injection: got %s, want %d", header.Number, height)
	}
	if !header.Number.IsUint64() {
		t.Fatalf("value=2 should leave header.Number a valid uint64")
	}
}

// TestMaybeInjectBigBlockNumberInflates is the core fault-injection assertion:
// with injection on (env "1", a non-"2" value) and a devnet chain, Number is
// lifted by exactly 2^64 so the low 64 bits (the truncated height every
// Uint64()-based check sees) are unchanged, while the big.Int itself becomes an
// illegal >64-bit shape.
func TestMaybeInjectBigBlockNumberInflates(t *testing.T) {
	t.Setenv(injectBigBlockNumberEnv, "1")
	t.Setenv(injectModeEnv, injectModeAdd64) // Prepare-hook path
	p := newInjectionParlia(devnetChainID)
	const height = 12345
	header := &types.Header{Number: big.NewInt(height)}

	p.maybeInjectBigBlockNumber(header)

	// Low 64 bits unchanged: every truncating check downstream still sees H.
	if got := header.Number.Uint64(); got != height {
		t.Fatalf("truncated height changed: Uint64()=%d, want %d", got, height)
	}
	// But the big.Int is now oversized and no longer a valid uint64.
	if header.Number.IsUint64() {
		t.Fatalf("header.Number should no longer fit in uint64 after injection")
	}
	if bl := header.Number.BitLen(); bl <= 64 {
		t.Fatalf("header.Number BitLen=%d, want > 64 after +2^64", bl)
	}
	// Exact value: H + 2^64.
	want := new(big.Int).Add(big.NewInt(height), new(big.Int).Lsh(big.NewInt(1), 64))
	if header.Number.Cmp(want) != 0 {
		t.Fatalf("injected Number = %s, want %s", header.Number, want)
	}
}

// TestInjectedHeaderFailsSanityCheck proves the injected shape is exactly what
// Header.SanityCheck (the full-block-broadcast defense) is meant to reject:
// !IsUint64() -> "too large block number". This is the fault the injection
// probes for on paths that skip SanityCheck.
func TestInjectedHeaderFailsSanityCheck(t *testing.T) {
	t.Setenv(injectBigBlockNumberEnv, "1")
	t.Setenv(injectModeEnv, injectModeAdd64) // Prepare-hook path
	p := newInjectionParlia(devnetChainID)
	header := &types.Header{Number: big.NewInt(999)}

	// Sanity of the sanity check: a clean header passes.
	if err := header.SanityCheck(); err != nil {
		t.Fatalf("pre-injection header unexpectedly failed SanityCheck: %v", err)
	}

	p.maybeInjectBigBlockNumber(header)

	if err := header.SanityCheck(); err == nil {
		t.Fatalf("injected oversized Number passed SanityCheck; expected rejection")
	}
}

// TestSealInjectionZero64 is the core assertion for the zero64 attack: the Seal
// hook sets Number = H<<64, so Uint64()==0 (slips the genesis short-circuit)
// while the big.Int is oversized (fails IsUint64/SanityCheck).
func TestSealInjectionZero64(t *testing.T) {
	t.Setenv(injectBigBlockNumberEnv, "1") // ON
	t.Setenv(injectModeEnv, injectModeZero64)
	p := newInjectionParlia(devnetChainID)
	const height = 20472
	header := &types.Header{Number: big.NewInt(height)}

	p.maybeInjectSealBlockNumber(header)

	if got := header.Number.Uint64(); got != 0 {
		t.Fatalf("zero64: Uint64() must be 0 (escapes number==0 short-circuit), got %d", got)
	}
	if header.Number.IsUint64() {
		t.Fatalf("zero64: big.Int must be >64-bit, IsUint64() should be false")
	}
	if bl := header.Number.BitLen(); bl <= 64 {
		t.Fatalf("zero64: BitLen=%d, want > 64", bl)
	}
	want := new(big.Int).Lsh(big.NewInt(height), 64)
	if header.Number.Cmp(want) != 0 {
		t.Fatalf("zero64: Number = %s, want H<<64 = %s", header.Number, want)
	}
	if err := header.SanityCheck(); err == nil {
		t.Fatalf("zero64: malformed Number should fail SanityCheck")
	}
}

// TestPrepareHookNoopInZero64Mode verifies the Prepare hook does not touch the
// header in zero64 mode (injection is deferred to Seal); otherwise Seal's
// number==0 guard would make the byzantine node fail to seal.
func TestPrepareHookNoopInZero64Mode(t *testing.T) {
	t.Setenv(injectBigBlockNumberEnv, "1")
	t.Setenv(injectModeEnv, injectModeZero64)
	p := newInjectionParlia(devnetChainID)
	const height = 20472
	header := &types.Header{Number: big.NewInt(height)}

	p.maybeInjectBigBlockNumber(header) // Prepare hook

	if header.Number.Cmp(big.NewInt(height)) != 0 {
		t.Fatalf("zero64: Prepare hook must leave header.Number = H, got %s", header.Number)
	}
}

// TestSealHookNoopInAdd64Mode verifies the Seal hook is inert in the default
// add64 mode (injection happens in Prepare there).
func TestSealHookNoopInAdd64Mode(t *testing.T) {
	t.Setenv(injectBigBlockNumberEnv, "1")
	t.Setenv(injectModeEnv, injectModeAdd64) // explicit add64 (default is zero64)
	p := newInjectionParlia(devnetChainID)
	const height = 20472
	header := &types.Header{Number: big.NewInt(height)}

	p.maybeInjectSealBlockNumber(header)

	if header.Number.Cmp(big.NewInt(height)) != 0 {
		t.Fatalf("add64: Seal hook must be a no-op, got %s", header.Number)
	}
}

// TestSealInjectionZero64GuardedOnProdChains verifies the hard guard also
// covers the zero64 Seal hook.
func TestSealInjectionZero64GuardedOnProdChains(t *testing.T) {
	t.Setenv(injectBigBlockNumberEnv, "1")
	t.Setenv(injectModeEnv, injectModeZero64)
	p := newInjectionParlia(params.BSCChainConfig.ChainID.Int64())
	const height = 20472
	header := &types.Header{Number: big.NewInt(height)}

	p.maybeInjectSealBlockNumber(header)

	if header.Number.Cmp(big.NewInt(height)) != 0 {
		t.Fatalf("guard: zero64 must be no-op on mainnet, got %s", header.Number)
	}
}

// TestMaybeInjectBigBlockNumberGuardsProdChains verifies the hard safety guard:
// on BSC mainnet and Chapel the hook is a no-op even with the flag on, so a
// misconfigured production/testnet node can never emit the malformed block.
func TestMaybeInjectBigBlockNumberGuardsProdChains(t *testing.T) {
	t.Setenv(injectBigBlockNumberEnv, "1")

	for _, tc := range []struct {
		name    string
		chainID *big.Int
	}{
		{"bsc-mainnet", params.BSCChainConfig.ChainID},
		{"chapel", params.ChapelChainConfig.ChainID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newInjectionParlia(tc.chainID.Int64())
			const height = 777
			header := &types.Header{Number: big.NewInt(height)}

			p.maybeInjectBigBlockNumber(header)

			if header.Number.Cmp(big.NewInt(height)) != 0 {
				t.Fatalf("guard failed on %s: Number mutated to %s, want %d",
					tc.name, header.Number, height)
			}
			if !header.Number.IsUint64() {
				t.Fatalf("guard failed on %s: Number no longer a valid uint64", tc.name)
			}
		})
	}
}
