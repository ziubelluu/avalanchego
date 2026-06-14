// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core/rawdb"
	"github.com/ava-labs/libevm/core/types"
	"github.com/stretchr/testify/require"

	"github.com/ava-labs/avalanchego/snow/validators"
	"github.com/ava-labs/avalanchego/utils/constants"
)

func fixedHeight(h uint64) CurrentHeightFunc {
	return func(context.Context) (uint64, error) { return h, nil }
}

func warpSetReturning(ws validators.WarpSet) WarpSetFunc {
	return func(context.Context, uint64) (validators.WarpSet, error) { return ws, nil }
}

// End to end: redact a block, then the committee policy accepts the redacted
// parent link reading the persisted proof, and the roots are left unchanged.
func TestRedactorEndToEnd(t *testing.T) {
	t.Parallel()

	ws, byIndex := makeCommittee(t, 3)
	agg := &fakeAggregator{byIndex: byIndex, signWith: []int{0, 1, 2}}
	db := rawdb.NewMemoryDatabase()

	original := types.NewBlockWithHeader(sealedHeader())
	h0 := original.Hash()

	redactor := NewRedactor(db, agg, warpSetReturning(ws), fixedHeight(7), constants.UnitTestID, proofSourceChainID, 2, 3)

	redacted, err := redactor.Redact(context.Background(), original, nil)
	require.NoError(t, err)

	// The redacted block is on disk under the original hash with unchanged roots.
	got := rawdb.ReadBlock(db, h0, original.NumberU64())
	require.NotNil(t, got)
	require.Empty(t, got.Transactions())
	require.Equal(t, original.Root(), got.Root())
	require.Equal(t, original.ReceiptHash(), got.ReceiptHash())
	require.Equal(t, redacted.TxHash(), got.TxHash())

	// The proof is stored.
	has, err := HasRedactionProof(db, h0)
	require.NoError(t, err)
	require.True(t, has)

	// The committee policy accepts the redacted parent link.
	policy := NewCommitteePolicy(db, warpSetReturning(ws), constants.UnitTestID, proofSourceChainID, 2, 3)
	require.True(t, policy.Approved(context.Background(), got.Header()))
}

// Redaction maintains the tx index: the original tx's entry is removed and the
// redacted tx's new hash is indexed.
func TestRedactorMaintainsTxIndex(t *testing.T) {
	t.Parallel()

	ws, byIndex := makeCommittee(t, 3)
	agg := &fakeAggregator{byIndex: byIndex, signWith: []int{0, 1, 2}}
	db := rawdb.NewMemoryDatabase()

	to := common.Address{0x99}
	origTx := types.NewTx(&types.LegacyTx{Nonce: 0, To: &to, Value: big.NewInt(1), Gas: 30000, GasPrice: big.NewInt(1), Data: []byte{0xaa, 0xbb}})
	redactedTx := types.NewTx(&types.LegacyTx{Nonce: 0, To: &to, Value: big.NewInt(1), Gas: 30000, GasPrice: big.NewInt(1), Data: nil})
	require.NotEqual(t, origTx.Hash(), redactedTx.Hash())

	original := types.NewBlockWithHeader(sealedHeader()).WithBody(types.Body{Transactions: []*types.Transaction{origTx}})

	// Simulate the original block having been indexed at accept time.
	rawdb.WriteTxLookupEntriesByBlock(db, original)
	require.NotNil(t, rawdb.ReadTxLookupEntry(db, origTx.Hash()))

	redactor := NewRedactor(db, agg, warpSetReturning(ws), fixedHeight(7), constants.UnitTestID, proofSourceChainID, 2, 3)
	_, err := redactor.Redact(context.Background(), original, []*types.Transaction{redactedTx})
	require.NoError(t, err)

	// Old hash no longer resolves; the redacted tx's new hash is indexed.
	require.Nil(t, rawdb.ReadTxLookupEntry(db, origTx.Hash()))
	require.NotNil(t, rawdb.ReadTxLookupEntry(db, redactedTx.Hash()))

	// The stored proof records exactly which transaction was redacted.
	raw, err := ReadRedactionProof(db, original.Hash())
	require.NoError(t, err)
	proof, err := ProofFromBytes(raw)
	require.NoError(t, err)
	require.Equal(t, []uint64{0}, proof.Proposal.RedactedIndices)
}

// If the proof cannot be produced, nothing is persisted.
func TestRedactorAggregatorErrorPersistsNothing(t *testing.T) {
	t.Parallel()

	ws, byIndex := makeCommittee(t, 3)
	agg := &fakeAggregator{byIndex: byIndex, err: errors.New("not enough stake")}
	db := rawdb.NewMemoryDatabase()

	original := types.NewBlockWithHeader(sealedHeader())
	h0 := original.Hash()

	redactor := NewRedactor(db, agg, warpSetReturning(ws), fixedHeight(7), constants.UnitTestID, proofSourceChainID, 2, 3)

	_, err := redactor.Redact(context.Background(), original, nil)
	require.Error(t, err)

	has, err := HasRedactionProof(db, h0)
	require.NoError(t, err)
	require.False(t, has)
}
