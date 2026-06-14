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
