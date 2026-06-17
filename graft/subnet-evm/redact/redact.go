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
// recomputed. Root, ReceiptHash and InitialTxHash stay the same. The block is
// not re-executed, the committed roots are preserved.
func RedactBlock(original *types.Block, newTxs []*types.Transaction) *types.Block {
	header := types.CopyHeader(original.Header())
	header.TxHash = types.DeriveSha(types.Transactions(newTxs), trie.NewStackTrie(nil))
	return types.NewBlockWithHeader(header).WithBody(types.Body{
		Transactions: newTxs,
		Uncles:       original.Uncles(),
	})
}

// Persist stores the redacted header and body under the original hash, so
// the children's ParentHash keep resolving through the old link.
// Receipts and the tx index are left untouched on purpose.
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

// ReindexRedacted fixes the tx index after a redaction: it drops the original
// transactions' entries and indexes the new body. Delete first, then write, so
// surviving transactions stay indexed.
func ReindexRedacted(db ethdb.KeyValueWriter, original, redacted *types.Block) {
	oldHashes := make([]common.Hash, len(original.Transactions()))
	for i, tx := range original.Transactions() {
		oldHashes[i] = tx.Hash()
	}
	rawdb.DeleteTxLookupEntries(db, oldHashes)
	rawdb.WriteTxLookupEntriesByBlock(db, redacted)
}
