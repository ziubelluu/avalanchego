// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"context"
	"errors"
	"testing"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core/rawdb"
	"github.com/ava-labs/libevm/core/types"
	"github.com/stretchr/testify/require"

	"github.com/ava-labs/avalanchego/snow/validators"
	"github.com/ava-labs/avalanchego/utils/constants"
	"github.com/ava-labs/avalanchego/utils/crypto/bls"
	"github.com/ava-labs/avalanchego/utils/set"
	"github.com/ava-labs/avalanchego/vms/platformvm/warp"
)

// redactedParent returns a header that looks redacted (TxHash changed, the old
// link still pointing at the pre-redaction hash) together with that old hash.
func redactedParent() (*types.Header, common.Hash) {
	parent := sealedHeader()
	h0 := parent.Hash() // before redaction: NewLink == OldLink == h0
	parent.TxHash = common.Hash{0xbe, 0xef}
	return parent, h0
}

// setup builds a committee, signs a proof for the redacted parent and stores it.
func setupApprovedPolicy(t *testing.T, quorumNum, quorumDen uint64) (Policy, *types.Header) {
	t.Helper()

	parent, h0 := redactedParent()
	ws, byIndex := makeCommittee(t, 3)

	proposal := &Proposal{OriginalHash: h0, NewTxHash: parent.TxHash, PChainHeight: 7}
	proof := signProof(t, proposal, byIndex, 0, 1, 2)

	db := rawdb.NewMemoryDatabase()
	raw, err := proof.Bytes()
	require.NoError(t, err)
	require.NoError(t, WriteRedactionProof(db, h0, raw))

	warpSet := func(_ context.Context, _ uint64) (validators.WarpSet, error) { return ws, nil }
	policy := NewCommitteePolicy(db, warpSet, constants.UnitTestID, proofSourceChainID, quorumNum, quorumDen)
	return policy, parent
}

// A valid stored proof reaching quorum approves the redaction.
func TestCommitteePolicyApproves(t *testing.T) {
	t.Parallel()

	policy, parent := setupApprovedPolicy(t, 2, 3)
	require.True(t, policy.Approved(context.Background(), parent))
}

// No stored proof -> not approved.
func TestCommitteePolicyNoProof(t *testing.T) {
	t.Parallel()

	parent, _ := redactedParent()
	db := rawdb.NewMemoryDatabase()
	warpSet := func(_ context.Context, _ uint64) (validators.WarpSet, error) {
		return validators.WarpSet{}, nil
	}
	policy := NewCommitteePolicy(db, warpSet, constants.UnitTestID, proofSourceChainID, 2, 3)
	require.False(t, policy.Approved(context.Background(), parent))
}

// A proof whose NewTxHash does not match the body in the header is rejected
// (cannot replay a proof for a different body).
func TestCommitteePolicyWrongBodyBinding(t *testing.T) {
	t.Parallel()

	parent, h0 := redactedParent()
	ws, byIndex := makeCommittee(t, 3)

	// Proposal approves a DIFFERENT body than the one in parent.TxHash.
	proposal := &Proposal{OriginalHash: h0, NewTxHash: common.Hash{0x12, 0x34}, PChainHeight: 7}
	proof := signProof(t, proposal, byIndex, 0, 1, 2)

	db := rawdb.NewMemoryDatabase()
	raw, err := proof.Bytes()
	require.NoError(t, err)
	require.NoError(t, WriteRedactionProof(db, h0, raw))

	warpSet := func(_ context.Context, _ uint64) (validators.WarpSet, error) { return ws, nil }
	policy := NewCommitteePolicy(db, warpSet, constants.UnitTestID, proofSourceChainID, 2, 3)
	require.False(t, policy.Approved(context.Background(), parent))
}

// If the validator set at the proposal height is no longer queryable, the
// redaction cannot be re-verified and is rejected.
func TestCommitteePolicyHeightNotQueryable(t *testing.T) {
	t.Parallel()

	parent, h0 := redactedParent()
	_, byIndex := makeCommittee(t, 3)

	proposal := &Proposal{OriginalHash: h0, NewTxHash: parent.TxHash, PChainHeight: 7}
	proof := signProof(t, proposal, byIndex, 0, 1, 2)

	db := rawdb.NewMemoryDatabase()
	raw, err := proof.Bytes()
	require.NoError(t, err)
	require.NoError(t, WriteRedactionProof(db, h0, raw))

	warpSet := func(_ context.Context, _ uint64) (validators.WarpSet, error) {
		return validators.WarpSet{}, errors.New("validator set pruned at height")
	}
	policy := NewCommitteePolicy(db, warpSet, constants.UnitTestID, proofSourceChainID, 2, 3)
	require.False(t, policy.Approved(context.Background(), parent))
}

// A valid proof that does not reach the quorum is rejected.
func TestCommitteePolicyBelowQuorum(t *testing.T) {
	t.Parallel()

	parent, h0 := redactedParent()
	ws, byIndex := makeCommittee(t, 3)

	proposal := &Proposal{OriginalHash: h0, NewTxHash: parent.TxHash, PChainHeight: 7}
	proof := signProof(t, proposal, byIndex, 0) // only 1 of 3 signs

	db := rawdb.NewMemoryDatabase()
	raw, err := proof.Bytes()
	require.NoError(t, err)
	require.NoError(t, WriteRedactionProof(db, h0, raw))

	warpSet := func(_ context.Context, _ uint64) (validators.WarpSet, error) { return ws, nil }
	policy := NewCommitteePolicy(db, warpSet, constants.UnitTestID, proofSourceChainID, 2, 3)
	require.False(t, policy.Approved(context.Background(), parent))
}

// signStateProofFor signs a StateProposal with the given committee members.
func signStateProofFor(t testing.TB, sp *StateProposal, byIndex map[int]bls.Signer, indices ...int) *StateProof {
	t.Helper()

	msg, err := warp.NewUnsignedMessage(constants.UnitTestID, proofSourceChainID, sp.Bytes())
	require.NoError(t, err)
	msgBytes := msg.Bytes()

	signers := set.NewBits()
	sigs := make([]*bls.Signature, 0, len(indices))
	for _, idx := range indices {
		sig, err := byIndex[idx].Sign(msgBytes)
		require.NoError(t, err)
		sigs = append(sigs, sig)
		signers.Add(idx)
	}
	aggSig, err := bls.AggregateSignatures(sigs)
	require.NoError(t, err)

	proof := &StateProof{Proposal: *sp, SignerBitSet: signers.Bytes()}
	copy(proof.AggSignature[:], bls.SignatureToBytes(aggSig))
	return proof
}

// setupStatePolicy stores, under the old link of a redacted parent, the state
// proof for a deposit signed by [signers], and returns the policy over it.
func setupStatePolicy(t *testing.T, originalHash *common.Hash, signers ...int) (Policy, *types.Header) {
	t.Helper()

	parent, h0 := redactedParent()
	ws, byIndex := makeCommittee(t, 3)

	sp := sampleStateProposal()
	sp.OriginalHash = h0
	if originalHash != nil {
		sp.OriginalHash = *originalHash
	}
	proof := signStateProofFor(t, sp, byIndex, signers...)

	db := rawdb.NewMemoryDatabase()
	raw, err := proof.Bytes()
	require.NoError(t, err)
	require.NoError(t, WriteRedactionProof(db, h0, raw))

	warpSet := func(_ context.Context, _ uint64) (validators.WarpSet, error) { return ws, nil }
	return NewCommitteePolicy(db, warpSet, constants.UnitTestID, proofSourceChainID, 2, 3), parent
}

// A deposit redaction approved by the committee is accepted by the same
// policy that accepts the tx ones.
func TestCommitteePolicyApprovesStateProof(t *testing.T) {
	t.Parallel()

	policy, parent := setupStatePolicy(t, nil, 0, 1, 2)
	require.True(t, policy.Approved(context.Background(), parent))
}

// A deposit proof signed by 1 of 3 doesn't reach the 2/3 quorum.
func TestCommitteePolicyStateProofBelowQuorum(t *testing.T) {
	t.Parallel()

	policy, parent := setupStatePolicy(t, nil, 0)
	require.False(t, policy.Approved(context.Background(), parent))
}

// A deposit proof for some other block can't be used for this one.
func TestCommitteePolicyStateProofOtherBlock(t *testing.T) {
	t.Parallel()

	other := common.Hash{0x0b, 0xad}
	policy, parent := setupStatePolicy(t, &other, 0, 1, 2)
	require.False(t, policy.Approved(context.Background(), parent))
}

// The bytes of one kind of proof must not decode as the other kind.
func TestProofKindsDontMix(t *testing.T) {
	t.Parallel()

	_, byIndex := makeCommittee(t, 3)
	txRaw, err := signProof(t, sampleProposal(), byIndex, 0, 1, 2).Bytes()
	require.NoError(t, err)
	stateRaw, err := signStateProofFor(t, sampleStateProposal(), byIndex, 0, 1, 2).Bytes()
	require.NoError(t, err)

	_, err = StateProofFromBytes(txRaw)
	require.Error(t, err, "a tx proof must not decode as a state proof")
	_, err = ProofFromBytes(stateRaw)
	require.Error(t, err, "a state proof must not decode as a tx proof")

	// and each one still decodes as itself
	_, err = ProofFromBytes(txRaw)
	require.NoError(t, err)
	_, err = StateProofFromBytes(stateRaw)
	require.NoError(t, err)
}
