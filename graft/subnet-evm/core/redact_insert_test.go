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
	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact/chameleon"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact/redactabledeposit"

	ethparams "github.com/ava-labs/libevm/params"
)

// tipChain is a running chain of two blocks, with a third one generated but
// not inserted. Block 2 (the tip) carries a blob, so it can be redacted, and
// block 3 points to it.
type tipChain struct {
	db        ethdb.Database
	gspec     *Genesis
	bc        *BlockChain
	tip       *types.Block
	child     *types.Block
	committee *testCommittee
	mkTx      func(nonce uint64, data []byte) *types.Transaction
}

func setupTipChain(tb testing.TB) *tipChain {
	tb.Helper()
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
		require.NoError(tb, err)
		return tx
	}

	bc, err := createBlockChain(db, DefaultCacheConfig, gspec, common.Hash{})
	require.NoError(tb, err)
	committee := newTestCommittee(tb)
	bc.SetRedactionPolicy(committee.policy(db))

	_, chain, _, err := GenerateChainWithGenesis(gspec, bc.engine, 3, 10, func(i int, gen *BlockGen) {
		switch i {
		case 0:
			gen.AddTx(mkTx(0, nil))
		case 1:
			gen.AddTx(mkTx(1, blob))
		case 2:
			gen.AddTx(mkTx(2, nil))
		}
	})
	require.NoError(tb, err)

	_, err = bc.InsertChain(chain[:2])
	require.NoError(tb, err)
	for _, blk := range chain[:2] {
		require.NoError(tb, bc.Accept(blk))
	}
	bc.DrainAcceptorQueue()

	require.Equal(tb, chain[1].Hash(), chain[2].ParentHash())
	return &tipChain{db: db, gspec: gspec, bc: bc, tip: chain[1], child: chain[2], committee: committee, mkTx: mkTx}
}

// redactTip redacts the tip through RedactStored with a proof signed by the
// whole committee, blanking the blob.
func (c *tipChain) redactTip(tb testing.TB) *types.Block {
	tb.Helper()
	newTxs := []*types.Transaction{c.mkTx(1, nil)}
	redacted := redact.RedactBlock(c.tip, newTxs)
	p := &redact.Proposal{
		OriginalHash:    c.tip.Hash(),
		NewTxHash:       redacted.TxHash(),
		PChainHeight:    1,
		RedactedIndices: []uint64{0},
	}
	proof := signTxProof(tb, c.committee.networkID, c.committee.sourceChainID, p, c.committee.byIndex, 0, 1, 2)
	got, err := c.bc.RedactStored(c.tip, newTxs, proof)
	require.NoError(tb, err)
	return got
}

// TestInsertRejectsChildOfRedactedParentWithoutProof: the tip of the chain gets
// rewritten in the database with no proof at all. The next block points to it
// through the old link, but nobody approved the redaction, so the block must
// not be inserted.
func TestInsertRejectsChildOfRedactedParentWithoutProof(t *testing.T) {
	c := setupTipChain(t)
	defer c.bc.Stop()

	// Rewrite block 2 straight in the database, without any proof.
	redacted := redact.RedactBlock(c.tip, []*types.Transaction{c.mkTx(1, nil)})
	require.NoError(t, redact.Persist(c.db, c.tip.Hash(), redacted))
	c.bc.PurgeBlockCaches(c.tip.Hash(), []common.Hash{c.tip.Transactions()[0].Hash()})

	stored := c.bc.GetHeaderByHash(c.tip.Hash())
	require.NotNil(t, stored)
	require.True(t, redact.IsRedacted(stored), "the parent in the database is a redacted block")
	require.Equal(t, redact.OldLink(stored), c.child.ParentHash())

	err := c.bc.InsertBlock(c.child)
	require.Error(t, err, "the child of a redacted parent with no proof must be rejected")
	require.ErrorContains(t, err, "redacted parent")
}

// TestInsertAcceptsChildOfApprovedRedactedParent: same thing with the proof of
// the committee, and the child goes in.
func TestInsertAcceptsChildOfApprovedRedactedParent(t *testing.T) {
	c := setupTipChain(t)
	defer c.bc.Stop()

	c.redactTip(t)
	require.True(t, redact.IsRedacted(c.bc.GetHeaderByHash(c.tip.Hash())))

	require.NoError(t, c.bc.InsertBlock(c.child))
	require.NoError(t, c.bc.Accept(c.child))
	c.bc.DrainAcceptorQueue()
	require.Equal(t, c.child.Hash(), c.bc.CurrentBlock().Hash())
}

// TestInsertRejectsChildWhenRedactedParentBodyTampered: the redaction was
// approved, but then the body under the old link gets replaced with something
// the committee never signed. The child must not be inserted.
func TestInsertRejectsChildWhenRedactedParentBodyTampered(t *testing.T) {
	c := setupTipChain(t)
	defer c.bc.Stop()

	c.redactTip(t)

	// Tamper: a different calldata than the (empty) one that was approved.
	tampered := redact.RedactBlock(c.tip, []*types.Transaction{c.mkTx(1, []byte("not what the committee signed"))})
	require.NoError(t, redact.Persist(c.db, c.tip.Hash(), tampered))
	c.bc.PurgeBlockCaches(c.tip.Hash(), nil)

	err := c.bc.InsertBlock(c.child)
	require.Error(t, err, "a redacted parent whose body is not the approved one must be rejected")
	require.ErrorContains(t, err, "redacted parent")
}

// TestInsertRejectsChildWhenParentDepositOpeningInvalid: the parent holds a
// deposit whose store tx was rewritten with an opening that doesn't give the
// digest. The proof is fine, the content is not.
func TestInsertRejectsChildWhenParentDepositOpeningInvalid(t *testing.T) {
	require := require.New(t)

	hk, _, err := chameleon.KeyGen()
	require.NoError(err)
	blob := bytes.Repeat([]byte{0xAB, 0xCD, 0xEF, 0x12}, 256)
	digest, r, err := chameleon.Hash(hk, blob)
	require.NoError(err)
	id := crypto.Keccak256Hash([]byte("deposit-1"))
	dc := setupDepositChainPendingChild(t, hk.Bytes(), id, blob, r, digest)
	defer dc.bc.Stop()

	committee := newTestCommittee(t)
	dc.bc.SetRedactionPolicy(committee.policy(dc.db))
	dc.bc.SetRedactionContentVerifier(redactabledeposit.VerifyRedactedBlock)

	// The committee approves "blob -> empty", but the store tx gets an opening
	// that does not verify.
	sp := &redact.StateProposal{
		OriginalHash: dc.block0.Hash(), DepositAddr: dc.depositAddr, ID: id, Digest: digest,
		NewBlobHash: crypto.Keccak256Hash([]byte{}), PChainHeight: 1,
	}
	proof := signStateProof(t, committee.networkID, committee.sourceChainID, sp, committee.byIndex, 0, 1, 2)
	proofBytes, err := proof.Bytes()
	require.NoError(err)

	badR := bytes.Repeat([]byte{0x0B}, chameleon.RandomnessLen)
	require.False(chameleon.Verify(hk, []byte{}, badR, digest))
	badCalldata, err := redactabledeposit.RedactedStoreCalldata(dc.storeTx.Data(), []byte{}, badR)
	require.NoError(err)
	redacted := redact.RedactBlock(dc.block0, dc.newTxsWithRedactedStore(dc.redactedStoreTx(t, badCalldata)))
	require.NoError(redact.Persist(dc.db, dc.block0.Hash(), redacted))
	require.NoError(redact.WriteRedactionProof(dc.db, dc.block0.Hash(), proofBytes))
	dc.bc.PurgeBlockCaches(dc.block0.Hash(), nil)

	err = dc.bc.InsertBlock(dc.block1)
	require.Error(err, "a parent whose deposit opening does not verify must be rejected")
	require.ErrorContains(err, "content")
}

// BenchmarkInsertBlockParent measures inserting a block whose parent is an
// ordinary block and one whose parent is a redacted block approved by the
// committee, both with the real policy. The difference is the cost of the
// parent check.
func BenchmarkInsertBlockParent(b *testing.B) {
	for _, redacted := range []bool{false, true} {
		name := "ordinary_parent"
		if redacted {
			name = "redacted_parent"
		}
		b.Run(name, func(b *testing.B) {
			c := setupTipChain(b)
			defer c.bc.Stop()
			if redacted {
				c.redactTip(b)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := c.bc.InsertBlockManual(c.child, false); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
