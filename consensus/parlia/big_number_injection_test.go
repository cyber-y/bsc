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

// TestMaybeInjectBigBlockNumberDisabledByDefault verifies the hook is inert
// when the opt-in env var is unset: production/QA runs without the flag must be
// byte-for-byte unaffected.
func TestMaybeInjectBigBlockNumberDisabledByDefault(t *testing.T) {
	// No t.Setenv for the flag -> it is unset for this test.
	p := newInjectionParlia(devnetChainID)
	const height = 12345
	header := &types.Header{Number: big.NewInt(height)}

	p.maybeInjectBigBlockNumber(header)

	if header.Number.Cmp(big.NewInt(height)) != 0 {
		t.Fatalf("header.Number mutated while injection disabled: got %s, want %d",
			header.Number, height)
	}
	if !header.Number.IsUint64() {
		t.Fatalf("header.Number should remain a valid uint64 when injection is off")
	}
}

// TestMaybeInjectBigBlockNumberInflates is the core fault-injection assertion:
// with the flag on and a devnet chain, Number is lifted by exactly 2^64 so the
// low 64 bits (the truncated height every Uint64()-based check sees) are
// unchanged, while the big.Int itself becomes an illegal >64-bit shape.
func TestMaybeInjectBigBlockNumberInflates(t *testing.T) {
	t.Setenv(injectBigBlockNumberEnv, "1")
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
