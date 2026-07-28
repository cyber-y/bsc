package parlia

import (
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

// Fault injection for the big.Int -> uint64 truncation weakness around
// Header.Number, exercised on the NORMAL miner block-production path only
// (Prepare). NOT for production. Opt-in via env; hard-disabled on
// mainnet/chapel regardless of env.
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
// number-shape check). Every uint64-based check downstream (this node's own
// Finalize/Seal snapshot lookups, verifyCascadingFields/getParent's parent-
// number continuity check, the fetcher's block_fetcher.go comparison,
// core/blockchain.go InsertChain's contiguity check) truncates consistently
// to the real height, so they all pass. core/blockchain.go InsertChain does
// NOT call Block.SanityCheck() -- only the direct full-block propagation
// path (NewBlockMsg's NewBlockPacket.sanityCheck) does.
//
// Expected outcome when this block is produced by a real, legitimately
// signing validator on a devnet/QA chain:
//   - This node: seals and inserts the block normally (locally self-consistent).
//   - Peers reached via full-block broadcast (NewBlockMsg): rejected at
//     message-decode time by Block.SanityCheck -> !IsUint64().
//   - Peers reached via announce-only (NewBlockHashesMsg) that then fetch the
//     header+body themselves via the block fetcher: SanityCheck is never
//     called on that path, verifyHeader (incl. signature check) passes, and
//     InsertChain accepts it -- the malformed Number is written into that
//     peer's canonical chain at the (truncated) real height.
//
// Scope note: this hook is intentionally mounted ONLY on Prepare (the local
// miner path). The MEV BidBlock path (PrepareForBidBlock) is deliberately not
// injected.
const injectBigBlockNumberEnv = "MALICIOUS_BIG_NUMBER" // "1" to enable (opt-in, default off)

var twoPow64 = new(big.Int).Lsh(big.NewInt(1), 64)

// maybeInjectBigBlockNumber inflates header.Number by 2^64 in place. Must be
// called from Prepare, before FinalizeAndAssemble/Seal compute the seal
// signature, so the signature remains valid for the inflated value.
func (p *Parlia) maybeInjectBigBlockNumber(header *types.Header) {
	// Hard safety guard: never inject on mainnet/chapel, ignore env entirely.
	if p.chainConfig != nil && p.chainConfig.ChainID != nil {
		if p.chainConfig.ChainID.Cmp(params.BSCChainConfig.ChainID) == 0 ||
			p.chainConfig.ChainID.Cmp(params.ChapelChainConfig.ChainID) == 0 {
			return
		}
	}
	if os.Getenv(injectBigBlockNumberEnv) != "1" || header.Number == nil {
		return
	}

	origUint64 := header.Number.Uint64()
	header.Number = new(big.Int).Add(header.Number, twoPow64)

	log.Warn("MALICIOUS_BIG_NUMBER active: inflated header.Number beyond uint64",
		"expectedHeight", origUint64,
		"truncatedUint64", header.Number.Uint64(),
		"bitlen", header.Number.BitLen(),
		"bigNumber", header.Number.String(),
		"parentHash", header.ParentHash,
		"coinbase", header.Coinbase,
	)
}
