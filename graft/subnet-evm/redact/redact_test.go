// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"math/big"
	"testing"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core/rawdb"
	"github.com/ava-labs/libevm/core/types"
	"github.com/stretchr/testify/require"
)

// Our headerKey must match the key libevm uses internally. We write a header
// with rawdb.WriteHeader and check that reading at our key gives the same bytes.
func TestHeaderKeyMatchesLibevm(t *testing.T) {
	t.Parallel()

	db := rawdb.NewMemoryDatabase()
	h := sealedHeader()
	rawdb.WriteHeader(db, h)

	want := rawdb.ReadHeaderRLP(db, h.Hash(), h.Number.Uint64())
	require.NotEmpty(t, want)

	got, err := db.Get(headerKey(h.Number.Uint64(), h.Hash()))
	require.NoError(t, err)
	require.Equal(t, []byte(want), got)
}

// ReindexRedacted drops the original transaction's entry and indexes the new
// (redacted) transaction.
func TestReindexRedacted(t *testing.T) {
	t.Parallel()

	db := rawdb.NewMemoryDatabase()
	to := common.Address{0x99}
	origTx := types.NewTx(&types.LegacyTx{Nonce: 0, To: &to, Value: big.NewInt(1), Gas: 30000, GasPrice: big.NewInt(1), Data: []byte{0xaa, 0xbb}})
	redactedTx := types.NewTx(&types.LegacyTx{Nonce: 0, To: &to, Value: big.NewInt(1), Gas: 30000, GasPrice: big.NewInt(1)})
	require.NotEqual(t, origTx.Hash(), redactedTx.Hash())

	original := types.NewBlockWithHeader(sealedHeader()).WithBody(types.Body{Transactions: []*types.Transaction{origTx}})
	rawdb.WriteTxLookupEntriesByBlock(db, original)
	require.NotNil(t, rawdb.ReadTxLookupEntry(db, origTx.Hash()))

	redacted := RedactBlock(original, []*types.Transaction{redactedTx})
	ReindexRedacted(db, original, redacted)

	require.Nil(t, rawdb.ReadTxLookupEntry(db, origTx.Hash()))
	require.NotNil(t, rawdb.ReadTxLookupEntry(db, redactedTx.Hash()))
}
