// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package core

import (
	"bytes"
	"context"
	"testing"

	"github.com/ava-labs/libevm/core/rawdb"
	"github.com/ava-labs/libevm/crypto"
	"github.com/stretchr/testify/require"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact/chameleon"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact/redactabledeposit"
	"github.com/ava-labs/avalanchego/snow/validators"
)

// depositRedaction does what the node does for a deposit: builds the proposal,
// gets it signed by [signers], forges the new opening and applies it with
// RedactStored. It returns the chain, ready to be reopened and validated.
func depositRedaction(t *testing.T, committee *testCommittee, blobPrime []byte, signers ...int) (*depositChain, *redact.StateProposal) {
	t.Helper()
	return depositRedactionWith(t, committee, blobPrime, blobPrime, signers...)
}

// depositRedactionWithContent approves [approved] but puts [applied] in the
// block, with a real forge so the opening still verifies.
func depositRedactionWithContent(t *testing.T, committee *testCommittee, approved, applied []byte) (*depositChain, *redact.StateProposal) {
	t.Helper()
	return depositRedactionWith(t, committee, approved, applied, 0, 1, 2)
}

func depositRedactionWith(t *testing.T, committee *testCommittee, approved, applied []byte, signers ...int) (*depositChain, *redact.StateProposal) {
	t.Helper()
	require := require.New(t)

	hk, tk, err := chameleon.KeyGen()
	require.NoError(err)
	blob := bytes.Repeat([]byte{0xAB, 0xCD, 0xEF, 0x12}, 256)
	digest, r, err := chameleon.Hash(hk, blob)
	require.NoError(err)
	id := crypto.Keccak256Hash([]byte("deposit-1"))
	dc := setupDepositChain(t, hk.Bytes(), id, blob, r, digest)
	dc.bc.SetRedactionContentVerifier(redactabledeposit.VerifyRedactedBlock)

	sp := &redact.StateProposal{
		OriginalHash: dc.block0.Hash(),
		DepositAddr:  dc.depositAddr,
		ID:           id,
		Digest:       digest,
		NewBlobHash:  crypto.Keccak256Hash(approved),
		PChainHeight: 1,
	}
	proof := signStateProof(t, committee.networkID, committee.sourceChainID, sp, committee.byIndex, signers...)
	proofBytes, err := proof.Bytes()
	require.NoError(err)

	// The forge only needs the vote, checked through the per-proposal proof.
	require.NoError(redact.WriteStateRedactionProof(dc.db, sp.Hash(), proofBytes))
	warpSet := func(context.Context, uint64) (validators.WarpSet, error) { return committee.ws, nil }
	approver := redact.NewCommitteeStatePolicy(dc.db, warpSet, committee.networkID, committee.sourceChainID, 2, 3)
	rPrime, err := redact.NewForger(approver, tk).Forge(context.Background(), sp, blob, r, applied)
	if err != nil {
		// the forger refuses (no quorum, or content not the approved one):
		// forge anyway, the point is to test what the chain does with it
		rPrime, err = chameleon.Forge(tk, blob, r, applied, digest)
		require.NoError(err)
	}

	redactedTx, err := redactabledeposit.RebuildRedactedStoreTx(dc.storeTx, applied, rPrime)
	require.NoError(err)
	newTxs := dc.newTxsWithRedactedStore(redactedTx)
	_, err = dc.bc.RedactStored(dc.block0, newTxs, proofBytes)
	if bytes.Equal(approved, applied) {
		require.NoError(err)
		return dc, sp
	}

	// The content is not the approved one: RedactStored refuses it. Write it
	// straight into the database, like someone tampering with the node, so
	// the tests can see what validation does with it.
	require.Error(err, "RedactStored must refuse a content the committee did not approve")
	redacted := redact.RedactBlock(dc.block0, newTxs)
	require.NoError(redact.Persist(dc.db, dc.block0.Hash(), redacted))
	require.NoError(redact.WriteRedactionProof(dc.db, dc.block0.Hash(), proofBytes))
	redact.ReindexRedacted(dc.db, dc.block0, redacted)
	return dc, sp
}

// reopenWithPolicy stops the chain and reopens it with the real policy.
func reopenWithPolicy(t *testing.T, dc *depositChain, committee *testCommittee) *BlockChain {
	t.Helper()
	dc.bc.Stop()
	bc2, err := createBlockChain(dc.db, DefaultCacheConfig, dc.gspec, dc.block1.Hash())
	require.NoError(t, err)
	bc2.SetRedactionContentVerifier(redactabledeposit.VerifyRedactedBlock)
	bc2.SetRedactionPolicy(committee.policy(dc.db))
	return bc2
}

// TestDepositRedactionApprovedByCommittee: a deposit redaction approved by the
// whole committee is accepted by the real policy after a restart.
func TestDepositRedactionApprovedByCommittee(t *testing.T) {
	committee := newTestCommittee(t)
	dc, _ := depositRedaction(t, committee, []byte{}, 0, 1, 2)

	bc2 := reopenWithPolicy(t, dc, committee)
	defer bc2.Stop()
	require.NoError(t, bc2.ValidateCanonicalChain())
}

// TestDepositRedactionBelowQuorumRejected: signed by 1 of 3, not approved.
func TestDepositRedactionBelowQuorumRejected(t *testing.T) {
	committee := newTestCommittee(t)
	dc, _ := depositRedaction(t, committee, []byte{}, 0)

	bc2 := reopenWithPolicy(t, dc, committee)
	defer bc2.Stop()
	err := bc2.ValidateCanonicalChain()
	require.Error(t, err)
	require.ErrorContains(t, err, "parent block")
}

// TestDepositRedactionContentMustMatchProposal: the committee approved an
// empty replacement, but the block carries some other content whose opening
// still verifies. The link is fine, the quorum is fine, the content is not.
func TestDepositRedactionContentMustMatchProposal(t *testing.T) {
	committee := newTestCommittee(t)
	// approved: "", applied: "something else" (forged for real, so CH holds)
	dc, _ := depositRedactionWithContent(t, committee, []byte{}, []byte("something else"))

	bc2 := reopenWithPolicy(t, dc, committee)
	defer bc2.Stop()
	err := bc2.ValidateCanonicalChain()
	require.Error(t, err, "content different from the approved one must be rejected")
	require.ErrorContains(t, err, "approved")
}

// TestRedactStoredRefusesOtherKindOnSameBlock: a block redacted through a
// deposit can't then be redacted through the tx channel, and the database
// must not change.
func TestRedactStoredRefusesOtherKindOnSameBlock(t *testing.T) {
	committee := newTestCommittee(t)
	dc, _ := depositRedaction(t, committee, []byte{}, 0, 1, 2)
	defer dc.bc.Stop()
	oldLink := dc.block0.Hash()

	current := dc.bc.GetBlockByHash(oldLink)
	require.NotNil(t, current)
	before, err := redact.ReadRedactionProof(dc.db, oldLink)
	require.NoError(t, err)

	newTxs := blank(t, current, 0)
	p := &redact.Proposal{
		OriginalHash:    oldLink,
		NewTxHash:       redact.RedactBlock(current, newTxs).TxHash(),
		PChainHeight:    1,
		RedactedIndices: []uint64{0},
	}
	txProof := signTxProof(t, committee.networkID, committee.sourceChainID, p, committee.byIndex, 0, 1, 2)

	_, err = dc.bc.RedactStored(current, newTxs, txProof)
	require.Error(t, err)
	require.ErrorContains(t, err, "kind")

	after, err := redact.ReadRedactionProof(dc.db, oldLink)
	require.NoError(t, err)
	require.Equal(t, before, after, "the stored proof must not change")
	require.Equal(t, current.TxHash(), dc.bc.GetBlockByHash(oldLink).TxHash(), "the body must not change")
}

// TestDepositRedactionStillChecksOtherPositions: in a block redacted through a
// deposit, the other transactions are still fully checked. Here the tx index
// entry of the deploy tx (position 0) goes missing and validation must notice.
func TestDepositRedactionStillChecksOtherPositions(t *testing.T) {
	committee := newTestCommittee(t)
	dc, _ := depositRedaction(t, committee, []byte{}, 0, 1, 2)

	deployTx := dc.block0.Transactions()[0]
	require.NotEqual(t, dc.storeTx.Hash(), deployTx.Hash())
	rawdb.DeleteTxLookupEntry(dc.db, deployTx.Hash())

	bc2 := reopenWithPolicy(t, dc, committee)
	defer bc2.Stop()
	err := bc2.ValidateCanonicalChain()
	require.Error(t, err, "a broken position that was not redacted must be caught")
	require.ErrorContains(t, err, "failed to find transaction")
}
