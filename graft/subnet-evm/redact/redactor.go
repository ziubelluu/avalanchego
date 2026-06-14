// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"context"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core/rawdb"
	"github.com/ava-labs/libevm/core/types"
	"github.com/ava-labs/libevm/ethdb"

	"github.com/ava-labs/avalanchego/ids"
)

// CurrentHeightFunc returns the current P-Chain height. The committee is the
// validator set at this height.
type CurrentHeightFunc func(ctx context.Context) (uint64, error)

// Redactor runs an approved redaction end to end: build the redacted block, get
// the committee to sign it, then persist the block and the proof.
type Redactor struct {
	db            ethdb.Database
	aggregator    Aggregator
	warpSet       WarpSetFunc
	currentHeight CurrentHeightFunc
	networkID     uint32
	sourceChainID ids.ID
	quorumNum     uint64
	quorumDen     uint64
}

// NewRedactor builds a Redactor.
func NewRedactor(
	db ethdb.Database,
	aggregator Aggregator,
	warpSet WarpSetFunc,
	currentHeight CurrentHeightFunc,
	networkID uint32,
	sourceChainID ids.ID,
	quorumNum uint64,
	quorumDen uint64,
) *Redactor {
	return &Redactor{
		db:            db,
		aggregator:    aggregator,
		warpSet:       warpSet,
		currentHeight: currentHeight,
		networkID:     networkID,
		sourceChainID: sourceChainID,
		quorumNum:     quorumNum,
		quorumDen:     quorumDen,
	}
}

// Redact replaces original's body with newTxs, gets the committee proof, and
// persists the redacted block plus the proof under the original hash. Nothing
// is persisted if the proof can't be produced or verified.
func (r *Redactor) Redact(ctx context.Context, original *types.Block, newTxs []*types.Transaction) (*types.Block, error) {
	height, err := r.currentHeight(ctx)
	if err != nil {
		return nil, err
	}
	vdrs, err := r.warpSet(ctx, height)
	if err != nil {
		return nil, err
	}

	originalHash := original.Hash()
	redacted := RedactBlock(original, newTxs)

	proposal := &Proposal{
		OriginalHash:    originalHash,
		NewTxHash:       redacted.TxHash(),
		PChainHeight:    height,
		RedactedIndices: redactedIndices(original.Transactions(), newTxs),
	}

	proof, err := ProduceProof(ctx, r.aggregator, proposal, r.networkID, r.sourceChainID, vdrs, r.quorumNum, r.quorumDen)
	if err != nil {
		return nil, err
	}
	// Self-check: don't persist a proof we couldn't verify ourselves.
	if err := VerifyRedactionProof(proof, r.networkID, r.sourceChainID, vdrs, r.quorumNum, r.quorumDen); err != nil {
		return nil, err
	}

	proofBytes, err := proof.Bytes()
	if err != nil {
		return nil, err
	}
	if err := Persist(r.db, originalHash, redacted); err != nil {
		return nil, err
	}
	if err := WriteRedactionProof(r.db, originalHash, proofBytes); err != nil {
		return nil, err
	}

	// Fix the tx index: drop the old transactions' entries and index the new
	// body. Delete first, then write, so surviving transactions stay indexed.
	oldHashes := make([]common.Hash, len(original.Transactions()))
	for i, tx := range original.Transactions() {
		oldHashes[i] = tx.Hash()
	}
	rawdb.DeleteTxLookupEntries(r.db, oldHashes)
	rawdb.WriteTxLookupEntriesByBlock(r.db, redacted)

	return redacted, nil
}

// redactedIndices returns the positions in the new body whose transaction
// differs from the original, i.e. the ones changed by the redaction.
func redactedIndices(original, redacted []*types.Transaction) []uint64 {
	var indices []uint64
	for i := range redacted {
		if i >= len(original) || redacted[i].Hash() != original[i].Hash() {
			indices = append(indices, uint64(i))
		}
	}
	return indices
}
