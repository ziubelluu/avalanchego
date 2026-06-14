// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"encoding/binary"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core/rawdb"
	"github.com/ava-labs/libevm/core/types"
	"github.com/ava-labs/libevm/ethdb"
	"github.com/ava-labs/libevm/rlp"
	"github.com/ava-labs/libevm/trie"
)

// headerPrefix mirrors the libevm rawdb schema ('h' + num(8 BE) + hash).
// libevm content-addresses headers (rawdb.WriteHeader keys by header.Hash()),
// but a redacted block must stay stored under its ORIGINAL hash so the old link
// keeps working. The schema is stable; TestHeaderKeyMatchesLibevm checks our
// key against libevm's own.
var headerPrefix = []byte("h")

// headerKey builds the db key libevm uses for a header at (number, hash).
func headerKey(number uint64, hash common.Hash) []byte {
	enc := make([]byte, 8)
	binary.BigEndian.PutUint64(enc, number)
	key := append([]byte{}, headerPrefix...)
	key = append(key, enc...)
	return append(key, hash.Bytes()...)
}

// RedactBlock returns a copy of the block with the body replaced and TxHash
// recomputed. Root, ReceiptHash and InitialTxHash stay the same: the block is
// NOT re-executed, the committed roots stand as historical fact.
func RedactBlock(original *types.Block, newTxs []*types.Transaction) *types.Block {
	header := types.CopyHeader(original.Header())
	header.TxHash = types.DeriveSha(types.Transactions(newTxs), trie.NewStackTrie(nil))
	return types.NewBlockWithHeader(header).WithBody(types.Body{
		Transactions: newTxs,
		Uncles:       original.Uncles(),
	})
}

// Persist stores the redacted header and body under the ORIGINAL hash, so the
// canonical map and the children's ParentHash keep resolving through the old
// link. Receipts and the tx index are left untouched on purpose.
func Persist(db ethdb.KeyValueWriter, originalHash common.Hash, redacted *types.Block) error {
	number := redacted.NumberU64()
	data, err := rlp.EncodeToBytes(redacted.Header())
	if err != nil {
		return err
	}
	if err := db.Put(headerKey(number, originalHash), data); err != nil {
		return err
	}
	rawdb.WriteBody(db, originalHash, number, redacted.Body())
	return nil
}
