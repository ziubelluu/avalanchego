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
	"github.com/stretchr/testify/require"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/params"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact"

	ethparams "github.com/ava-labs/libevm/params"
)

// TestRedactSameBlockTwice redacts a block and then redacts it again, another
// position this time. The second redaction must land on top of the first one:
// the block is still found under its old link, both blobs are gone and nothing
// is left under the hash the block had in between.
func TestRedactSameBlockTwice(t *testing.T) {
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
		blobA = bytes.Repeat([]byte("FIRST-BLOB-AAAA-"), 16)
		blobB = bytes.Repeat([]byte("SECOND-BLOB-BBBB"), 16)
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
	mkProof := func(original common.Hash, newTxHash common.Hash, indices ...uint64) []byte {
		p := &redact.Proof{Proposal: redact.Proposal{
			OriginalHash:    original,
			NewTxHash:       newTxHash,
			RedactedIndices: indices,
		}}
		b, err := p.Bytes()
		require.NoError(t, err)
		return b
	}

	bc, err := createBlockChain(db, DefaultCacheConfig, gspec, common.Hash{})
	require.NoError(t, err)
	defer bc.Stop()
	// This test is about where the block is kept, not about who approved the
	// redaction.
	bc.SetRedactionPolicy(redact.AllowAllForTesting)

	_, chain, _, err := GenerateChainWithGenesis(gspec, bc.engine, 2, 10, func(i int, gen *BlockGen) {
		if i == 0 {
			gen.AddTx(mkTx(0, blobA))
			gen.AddTx(mkTx(1, blobB))
		} else {
			gen.AddTx(mkTx(2, nil))
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
	oldLink := target.Hash()
	number := target.NumberU64()

	// First redaction: position 0.
	firstTxs := []*types.Transaction{mkTx(0, nil), target.Transactions()[1]}
	firstRedacted, err := bc.RedactStored(target, firstTxs, mkProof(oldLink, redact.RedactBlock(target, firstTxs).TxHash(), 0))
	require.NoError(t, err)
	require.False(t, dbContains(db, blobA), "the first blob must be gone after the first redaction")
	require.True(t, dbContains(db, blobB))

	// Second redaction: get the block the same way the VM does, by its old link.
	current := bc.GetBlockByHash(oldLink)
	require.NotNil(t, current)
	inBetween := current.Hash()
	require.Equal(t, firstRedacted.Hash(), inBetween)
	require.NotEqual(t, oldLink, inBetween, "a redacted block has a new hash")
	require.Equal(t, oldLink, redact.OldLink(current.Header()), "but its old link is still the original hash")

	secondTxs := []*types.Transaction{current.Transactions()[0], mkTx(1, nil)}
	secondProof := mkProof(oldLink, redact.RedactBlock(current, secondTxs).TxHash(), 0, 1)
	_, err = bc.RedactStored(current, secondTxs, secondProof)
	require.NoError(t, err)

	// The block under the old link has both positions redacted.
	got := bc.GetBlockByHash(oldLink)
	require.NotNil(t, got)
	require.Empty(t, got.Transactions()[0].Data())
	require.Empty(t, got.Transactions()[1].Data(), "the node must serve the second redaction")
	onDisk := rawdb.ReadBlock(db, oldLink, number)
	require.NotNil(t, onDisk)
	require.Equal(t, got.TxHash(), onDisk.TxHash(), "the block on disk must be the second redaction")

	// Both blobs are gone.
	require.False(t, dbContains(db, blobA))
	require.False(t, dbContains(db, blobB), "the second blob must not stay in the database")

	// The proof under the old link is the second one.
	gotProof, err := redact.ReadRedactionProof(db, oldLink)
	require.NoError(t, err)
	require.Equal(t, secondProof, gotProof)

	// Nothing is stored under the hash the block had in between.
	require.Nil(t, rawdb.ReadHeader(db, inBetween, number), "no header under the in-between hash")
	require.Nil(t, rawdb.ReadBody(db, inBetween, number), "no body under the in-between hash")
	has, err := redact.HasRedactionProof(db, inBetween)
	require.NoError(t, err)
	require.False(t, has, "no proof under the in-between hash")
	// Not even in memory: the block cache must not keep the first redaction.
	require.Nil(t, bc.GetBlock(inBetween, number), "the first redaction must not be served from the cache")

	// The old link is the same after two redactions and the chain still validates.
	require.Equal(t, oldLink, redact.OldLink(got.Header()))
	require.NoError(t, bc.ValidateCanonicalChain())
}

// TestRedactStoredServesRedactedHeaderByNumber: after a redaction on a running
// node, looking the block up by number must give the same header as looking it
// up by hash.
func TestRedactStoredServesRedactedHeaderByNumber(t *testing.T) {
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
	// This test is about where the block is kept, not about who approved the
	// redaction.
	bc.SetRedactionPolicy(redact.AllowAllForTesting)

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
	number := target.NumberU64()
	require.Equal(t, target.Hash(), bc.GetHeaderByNumber(number).Hash())

	newTxs := []*types.Transaction{mkTx(0, nil)}
	proof := &redact.Proof{Proposal: redact.Proposal{
		OriginalHash: target.Hash(), NewTxHash: redact.RedactBlock(target, newTxs).TxHash(), RedactedIndices: []uint64{0},
	}}
	proofBytes, err := proof.Bytes()
	require.NoError(t, err)
	redacted, err := bc.RedactStored(target, newTxs, proofBytes)
	require.NoError(t, err)

	byHash := bc.GetHeaderByHash(target.Hash())
	byNumber := bc.GetHeaderByNumber(number)
	require.Equal(t, redacted.TxHash(), byHash.TxHash)
	require.Equal(t, redacted.TxHash(), byNumber.TxHash, "by number the node must serve the redacted header too")
	require.Equal(t, byHash.Hash(), byNumber.Hash())
	require.Equal(t, byHash.Hash(), bc.GetBlockByNumber(number).Hash())

	// So the chain validates without reopening it.
	require.NoError(t, bc.ValidateCanonicalChain())
}
