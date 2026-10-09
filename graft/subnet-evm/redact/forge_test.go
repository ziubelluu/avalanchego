// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"context"
	"testing"

	"github.com/ava-labs/libevm/crypto"
	"github.com/stretchr/testify/require"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact/chameleon"
)

type fixedApprover struct{ ok bool }

func (a fixedApprover) ApprovedState(context.Context, *StateProposal) bool { return a.ok }

// With the vote approved the forger makes a collision; without it, nothing.
func TestForgerNeedsApproval(t *testing.T) {
	hk, tk, err := chameleon.KeyGen()
	require.NoError(t, err)
	forger := NewForger(fixedApprover{ok: true}, tk)

	blob := []byte("original content")
	digest, r, err := chameleon.Hash(hk, blob)
	require.NoError(t, err)
	blobPrime := []byte{}
	sp := &StateProposal{NewBlobHash: crypto.Keccak256Hash(blobPrime), Digest: digest}

	rPrime, err := forger.Forge(t.Context(), sp, blob, r, blobPrime)
	require.NoError(t, err)
	require.True(t, chameleon.Verify(hk, blobPrime, rPrime, digest))

	_, err = NewForger(fixedApprover{ok: false}, tk).Forge(t.Context(), sp, blob, r, blobPrime)
	require.ErrorIs(t, err, ErrForgeNotApproved)
}
