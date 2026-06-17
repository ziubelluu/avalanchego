// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package core

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core/rawdb"
	"github.com/ava-labs/libevm/core/types"
	"github.com/ava-labs/libevm/crypto"
	"github.com/ava-labs/libevm/ethdb"
	"github.com/stretchr/testify/require"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/params"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact"

	ethparams "github.com/ava-labs/libevm/params"
)

// dbContains reports whether any value stored in db contains data.
func dbContains(db ethdb.Iteratee, data []byte) bool {
	it := db.NewIterator(nil, nil)
	defer it.Release()
	for it.Next() {
		if bytes.Contains(it.Value(), data) {
			return true
		}
	}
	return false
}

// TestRedactRemovesBlobFromStorage puts a recognizable blob in a transaction's
// input, accepts it on a real chain, then redacts it and checks the blob is
// gone from the database while the chain still validates.
func TestRedactRemovesBlobFromStorage(t *testing.T) {
	var (
		key, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr   = crypto.PubkeyToAddress(key.PublicKey)
		config = params.TestChainConfig
		signer = types.LatestSigner(config)
		db     = rawdb.NewMemoryDatabase()
		eoa    = common.Address{0x99}
		gspec  = &Genesis{
			Config:   config,
			Alloc:    types.GenesisAlloc{addr: {Balance: big.NewInt(1_000_000_000_000_000_000)}},
			GasLimit: params.GetExtra(config).FeeConfig.GasLimit.Uint64(),
		}
		blob = bytes.Repeat([]byte{0xAA, 0xBB, 0xCC, 0xDD}, 256)
	)

	mkTx := func(nonce uint64, data []byte) *types.Transaction {
		tx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{
			Nonce:     nonce,
			GasTipCap: big.NewInt(0),
			GasFeeCap: big.NewInt(225_000_000_000),
			Gas:       ethparams.TxGas + 16*uint64(len(data)),
			To:        &eoa,
			Value:     big.NewInt(0),
			Data:      data,
		}), signer, key)
		require.NoError(t, err)
		return tx
	}

	bc, err := createBlockChain(db, DefaultCacheConfig, gspec, common.Hash{})
	require.NoError(t, err)

	// Block 0 contains the blob; block 1 is the head.
	_, chain, _, err := GenerateChainWithGenesis(gspec, bc.engine, 2, 10, func(i int, gen *BlockGen) {
		if i == 0 {
			gen.AddTx(mkTx(0, blob))
		} else {
			gen.AddTx(mkTx(1, nil))
		}
	})
	require.NoError(t, err)

	_, err = bc.InsertChain(chain)
	require.NoError(t, err)
	for _, blk := range chain {
		require.NoError(t, bc.Accept(blk))
	}
	bc.DrainAcceptorQueue()

	target, head := chain[0], chain[1]
	t.Logf("built and accepted 2 blocks; block %d contains a %d-byte blob", target.NumberU64(), len(blob))

	// Before redaction the blob is in the database.
	require.True(t, dbContains(db, blob), "blob should be stored before redaction")
	oldInput := target.Transactions()[0].Data()
	t.Logf("before redaction: blob found in the database")
	t.Logf("old blob: %d bytes, starts with %x...", len(oldInput), oldInput[:16])

	// Redact: replace the tx with an input-less one and persist the redacted block.
	redacted := redact.RedactBlock(target, []*types.Transaction{mkTx(0, nil)})
	require.NoError(t, redact.Persist(db, target.Hash(), redacted))
	t.Logf("redacted block %d: TxHash %s -> %s, InitialTxHash kept", target.NumberU64(), target.TxHash().TerminalString(), redacted.TxHash().TerminalString())

	bc.Stop()

	// Reopen with cold caches so everything is read from disk.
	bc2, err := createBlockChain(db, DefaultCacheConfig, gspec, head.Hash())
	require.NoError(t, err)
	defer bc2.Stop()
	t.Log("reopened the chain with cold caches (reads from disk)")

	// The blob is gone, the chain validates and the next block's state root is unchanged.
	require.False(t, dbContains(db, blob), "blob should be gone after redaction")
	t.Log("after redaction: blob no longer in the database")

	got := rawdb.ReadBlock(db, target.Hash(), target.NumberU64())
	require.NotNil(t, got)
	newInput := got.Transactions()[0].Data()
	require.Empty(t, newInput)
	require.Equal(t, target.Root(), got.Root())
	t.Logf("new blob: %d bytes (%x)", len(newInput), newInput)
	t.Log("redacted block read back: input empty, state root unchanged")

	require.NoError(t, bc2.ValidateCanonicalChain())
	t.Log("chain still validates through the old link")

	gotHead := rawdb.ReadBlock(db, head.Hash(), head.NumberU64())
	require.NotNil(t, gotHead)
	require.Equal(t, head.Root(), gotHead.Root())
	t.Log("next block's state root is untouched")
}

// TestRedactNeedsCachePurgeOnLiveNode shows that on a running node the in-memory
// caches still serve the old block after a redaction, and that PurgeBlockCaches
// fixes it (without restarting).
func TestRedactNeedsCachePurgeOnLiveNode(t *testing.T) {
	var (
		key, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr   = crypto.PubkeyToAddress(key.PublicKey)
		config = params.TestChainConfig
		signer = types.LatestSigner(config)
		db     = rawdb.NewMemoryDatabase()
		eoa    = common.Address{0x99}
		gspec  = &Genesis{
			Config:   config,
			Alloc:    types.GenesisAlloc{addr: {Balance: big.NewInt(1_000_000_000_000_000_000)}},
			GasLimit: params.GetExtra(config).FeeConfig.GasLimit.Uint64(),
		}
		blob = bytes.Repeat([]byte{0xAA, 0xBB, 0xCC, 0xDD}, 256)
	)

	mkTx := func(nonce uint64, data []byte) *types.Transaction {
		tx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{
			Nonce:     nonce,
			GasTipCap: big.NewInt(0),
			GasFeeCap: big.NewInt(225_000_000_000),
			Gas:       ethparams.TxGas + 16*uint64(len(data)),
			To:        &eoa,
			Value:     big.NewInt(0),
			Data:      data,
		}), signer, key)
		require.NoError(t, err)
		return tx
	}

	bc, err := createBlockChain(db, DefaultCacheConfig, gspec, common.Hash{})
	require.NoError(t, err)
	defer bc.Stop()

	_, chain, _, err := GenerateChainWithGenesis(gspec, bc.engine, 2, 10, func(i int, gen *BlockGen) {
		if i == 0 {
			gen.AddTx(mkTx(0, blob))
		} else {
			gen.AddTx(mkTx(1, nil))
		}
	})
	require.NoError(t, err)

	_, err = bc.InsertChain(chain)
	require.NoError(t, err)
	for _, blk := range chain {
		require.NoError(t, bc.Accept(blk))
	}
	bc.DrainAcceptorQueue()

	target := chain[0]
	origTxHash := target.Transactions()[0].Hash()

	// Warm the caches by reading the block once.
	require.NotNil(t, bc.GetBlock(target.Hash(), target.NumberU64()))

	// Redact on disk (same running node, caches are still hot).
	redacted := redact.RedactBlock(target, []*types.Transaction{mkTx(0, nil)})
	require.NoError(t, redact.Persist(db, target.Hash(), redacted))

	// The gap: the node still serves the old block (containing the blob) from cache.
	cached := bc.GetBlock(target.Hash(), target.NumberU64())
	require.Equal(t, blob, cached.Transactions()[0].Data())
	t.Log("with hot caches the node still returns the old block (containing the blob)")

	// Purge the caches and the redaction takes effect without a restart.
	bc.PurgeBlockCaches(target.Hash(), []common.Hash{origTxHash})

	fresh := bc.GetBlock(target.Hash(), target.NumberU64())
	require.Empty(t, fresh.Transactions()[0].Data())
	t.Log("after PurgeBlockCaches the node returns the redacted block (containing no blob)")
}

// TestRedactStoredOnLiveNode drives the full apply through RedactStored: the
// running node serves the redacted block right away, the blob is gone and the
// chain still validates, without reopening.
func TestRedactStoredOnLiveNode(t *testing.T) {
	var (
		key, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr   = crypto.PubkeyToAddress(key.PublicKey)
		config = params.TestChainConfig
		signer = types.LatestSigner(config)
		db     = rawdb.NewMemoryDatabase()
		eoa    = common.Address{0x99}
		gspec  = &Genesis{
			Config:   config,
			Alloc:    types.GenesisAlloc{addr: {Balance: big.NewInt(1_000_000_000_000_000_000)}},
			GasLimit: params.GetExtra(config).FeeConfig.GasLimit.Uint64(),
		}
		blob = bytes.Repeat([]byte{0xDE, 0xAD, 0xBE, 0xEF}, 256)
	)

	mkTx := func(nonce uint64, data []byte) *types.Transaction {
		tx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{
			Nonce:     nonce,
			GasTipCap: big.NewInt(0),
			GasFeeCap: big.NewInt(225_000_000_000),
			Gas:       ethparams.TxGas + 16*uint64(len(data)),
			To:        &eoa,
			Value:     big.NewInt(0),
			Data:      data,
		}), signer, key)
		require.NoError(t, err)
		return tx
	}

	bc, err := createBlockChain(db, DefaultCacheConfig, gspec, common.Hash{})
	require.NoError(t, err)
	defer bc.Stop()

	_, chain, _, err := GenerateChainWithGenesis(gspec, bc.engine, 2, 10, func(i int, gen *BlockGen) {
		if i == 0 {
			gen.AddTx(mkTx(0, blob))
		} else {
			gen.AddTx(mkTx(1, nil))
		}
	})
	require.NoError(t, err)

	_, err = bc.InsertChain(chain)
	require.NoError(t, err)
	for _, blk := range chain {
		require.NoError(t, bc.Accept(blk))
	}
	bc.DrainAcceptorQueue()

	target := chain[0]
	require.NotNil(t, bc.GetBlock(target.Hash(), target.NumberU64())) // warm the caches

	// Build a proof for the redaction and apply it on the live node.
	proof := &redact.Proof{Proposal: redact.Proposal{OriginalHash: target.Hash(), RedactedIndices: []uint64{0}}}
	proofBytes, err := proof.Bytes()
	require.NoError(t, err)

	redacted, err := bc.RedactStored(target, []*types.Transaction{mkTx(0, nil)}, proofBytes)
	require.NoError(t, err)

	// No reopen: the node already serves the redacted block.
	got := bc.GetBlock(target.Hash(), target.NumberU64())
	require.NotNil(t, got)
	require.Empty(t, got.Transactions()[0].Data())
	require.Equal(t, redacted.TxHash(), got.TxHash())
	require.False(t, dbContains(db, blob))
}
