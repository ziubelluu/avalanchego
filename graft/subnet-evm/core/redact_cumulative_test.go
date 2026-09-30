// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package core

import (
	"bytes"
	"context"
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
	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/snow/validators"
	"github.com/ava-labs/avalanchego/utils/constants"
	"github.com/ava-labs/avalanchego/utils/crypto/bls"

	ethparams "github.com/ava-labs/libevm/params"
)

// cumulativeChain is a running chain whose block 1 has three transactions:
// two with a blob (positions 0 and 2) and a plain one in the middle. It uses
// the real committee policy.
type cumulativeChain struct {
	db            ethdb.Database
	gspec         *Genesis
	bc            *BlockChain
	target        *types.Block
	head          *types.Block
	blobA, blobB  []byte
	byIndex       map[int]bls.Signer
	policy        redact.Policy
	networkID     uint32
	sourceChainID ids.ID
}

func setupCumulativeChain(t *testing.T) *cumulativeChain {
	t.Helper()
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
		blobA = bytes.Repeat([]byte("AAAA-first-blob-"), 16)
		blobB = bytes.Repeat([]byte("BBBB-second-blob"), 16)
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

	networkID := constants.UnitTestID
	sourceChainID := ids.GenerateTestID()
	ws, byIndex := buildCommittee(t, 3)
	warpSet := func(context.Context, uint64) (validators.WarpSet, error) { return ws, nil }
	policy := redact.NewCommitteePolicy(db, warpSet, networkID, sourceChainID, 2, 3)

	bc, err := createBlockChain(db, DefaultCacheConfig, gspec, common.Hash{})
	require.NoError(t, err)
	bc.SetRedactionPolicy(policy)

	_, chain, _, err := GenerateChainWithGenesis(gspec, bc.engine, 2, 10, func(i int, gen *BlockGen) {
		if i == 0 {
			gen.AddTx(mkTx(0, blobA))
			gen.AddTx(mkTx(1, nil))
			gen.AddTx(mkTx(2, blobB))
		} else {
			gen.AddTx(mkTx(3, nil))
		}
	})
	require.NoError(t, err)
	_, err = bc.InsertChain(chain)
	require.NoError(t, err)
	for _, blk := range chain {
		require.NoError(t, bc.Accept(blk))
	}
	bc.DrainAcceptorQueue()

	return &cumulativeChain{
		db: db, gspec: gspec, bc: bc, target: chain[0], head: chain[1],
		blobA: blobA, blobB: blobB, byIndex: byIndex, policy: policy,
		networkID: networkID, sourceChainID: sourceChainID,
	}
}

// reopen stops the chain and opens it again from the database with the same
// policy, so that nothing comes from the caches.
func (c *cumulativeChain) reopen(t *testing.T) *BlockChain {
	t.Helper()
	c.bc.Stop()
	bc, err := createBlockChain(c.db, DefaultCacheConfig, c.gspec, c.head.Hash())
	require.NoError(t, err)
	bc.SetRedactionPolicy(c.policy)
	return bc
}

// proofFor builds and signs the proof for redacting [indices] of [current],
// which is the block stored under [oldLink].
func (c *cumulativeChain) proofFor(t *testing.T, oldLink common.Hash, current *types.Block, indices ...uint64) ([]*types.Transaction, []byte) {
	t.Helper()
	newTxs := blank(t, current, indices...)
	p := &redact.Proposal{
		OriginalHash:    oldLink,
		NewTxHash:       redact.RedactBlock(current, newTxs).TxHash(),
		PChainHeight:    1,
		RedactedIndices: indices,
	}
	return newTxs, signTxProof(t, c.networkID, c.sourceChainID, p, c.byIndex, 0, 1, 2)
}

// TestRedactSecondProposalMustBeCumulative: position 0 was redacted first.
// A second proposal that only lists position 2 forgets about position 0, so
// it must be refused and the database must stay as it was.
func TestRedactSecondProposalMustBeCumulative(t *testing.T) {
	c := setupCumulativeChain(t)
	oldLink := c.target.Hash()
	number := c.target.NumberU64()

	txs1, proof1 := c.proofFor(t, oldLink, c.target, 0)
	_, err := c.bc.RedactStored(c.target, txs1, proof1)
	require.NoError(t, err)
	require.False(t, dbContains(c.db, c.blobA))

	current := c.bc.GetBlockByHash(oldLink)
	require.NotNil(t, current)
	before := rawdb.ReadBlock(c.db, oldLink, number)

	// Second proposal with only position 2.
	txs2, proof2 := c.proofFor(t, oldLink, current, 2)
	_, err = c.bc.RedactStored(current, txs2, proof2)
	require.Error(t, err, "a proposal that leaves out position 0 must be refused")
	require.ErrorContains(t, err, "already redacted")

	// Nothing changed in the database.
	after := rawdb.ReadBlock(c.db, oldLink, number)
	require.Equal(t, before.TxHash(), after.TxHash())
	gotProof, err := redact.ReadRedactionProof(c.db, oldLink)
	require.NoError(t, err)
	require.Equal(t, proof1, gotProof)
	require.True(t, dbContains(c.db, c.blobB), "the refused redaction must not remove anything")

	bc2 := c.reopen(t)
	defer bc2.Stop()
	require.NoError(t, bc2.ValidateCanonicalChain())
}

// TestRedactSecondProposalCumulativeAccepted: the second proposal lists both
// positions, so it goes through; both blobs are gone and the chain validates
// with the real policy.
func TestRedactSecondProposalCumulativeAccepted(t *testing.T) {
	c := setupCumulativeChain(t)
	oldLink := c.target.Hash()

	txs1, proof1 := c.proofFor(t, oldLink, c.target, 0)
	_, err := c.bc.RedactStored(c.target, txs1, proof1)
	require.NoError(t, err)

	current := c.bc.GetBlockByHash(oldLink)
	require.NotNil(t, current)
	txs2, proof2 := c.proofFor(t, oldLink, current, 0, 2)
	_, err = c.bc.RedactStored(current, txs2, proof2)
	require.NoError(t, err)

	got := c.bc.GetBlockByHash(oldLink)
	require.Empty(t, got.Transactions()[0].Data(), "position 0 stays redacted")
	require.Empty(t, got.Transactions()[2].Data(), "position 2 is redacted now")
	require.False(t, dbContains(c.db, c.blobA))
	require.False(t, dbContains(c.db, c.blobB))

	bc2 := c.reopen(t)
	defer bc2.Stop()
	require.NoError(t, bc2.ValidateCanonicalChain())
}

// TestRedactCannotRestoreRedactedPosition: a cumulative proposal that puts the
// original calldata back at an already redacted position is refused.
func TestRedactCannotRestoreRedactedPosition(t *testing.T) {
	c := setupCumulativeChain(t)
	defer c.bc.Stop()
	oldLink := c.target.Hash()

	txs1, proof1 := c.proofFor(t, oldLink, c.target, 0)
	_, err := c.bc.RedactStored(c.target, txs1, proof1)
	require.NoError(t, err)

	// position 0 goes back to the original tx, position 2 gets blanked
	current := c.bc.GetBlockByHash(oldLink)
	restored := blank(t, current, 2)
	restored[0] = c.target.Transactions()[0]
	p := &redact.Proposal{
		OriginalHash:    oldLink,
		NewTxHash:       redact.RedactBlock(current, restored).TxHash(),
		PChainHeight:    1,
		RedactedIndices: []uint64{0, 2},
	}
	proof := signTxProof(t, c.networkID, c.sourceChainID, p, c.byIndex, 0, 1, 2)

	_, err = c.bc.RedactStored(current, restored, proof)
	require.Error(t, err, "an already redacted position must not change")
	require.ErrorContains(t, err, "already redacted")
	require.False(t, dbContains(c.db, c.blobA), "the first blob must not come back")
}
