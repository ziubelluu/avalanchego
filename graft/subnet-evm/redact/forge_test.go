// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/ava-labs/libevm/crypto"
	"github.com/stretchr/testify/require"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact/chameleon"
)

type fixedApprover struct{ ok bool }

func (a fixedApprover) ApprovedState(context.Context, *StateProposal) bool { return a.ok }

// NewForgerFromEnv loads the trapdoor from a local secret and refuses to build
// when the secret is missing.
func TestNewForgerFromEnv(t *testing.T) {
	const envVar = "REDACT_TRAPDOOR_FORGE_TEST"

	hk, tk, err := chameleon.KeyGen()
	require.NoError(t, err)

	// No secret in the environment -> cannot build a forger.
	_, err = NewForgerFromEnv(fixedApprover{ok: true}, envVar)
	require.Error(t, err)

	// With the secret set, the forger builds and can forge an approved redaction.
	t.Setenv(envVar, hex.EncodeToString(tk.Bytes()))
	forger, err := NewForgerFromEnv(fixedApprover{ok: true}, envVar)
	require.NoError(t, err)

	blob := []byte("original content")
	r := make([]byte, 32)
	r[0] = 1
	digest := chameleon.Hash(hk, blob, r)
	blobPrime := []byte{}
	sp := &StateProposal{NewBlobHash: crypto.Keccak256Hash(blobPrime)}

	rPrime, err := forger.Forge(context.Background(), sp, blob, r, blobPrime)
	require.NoError(t, err)
	require.True(t, chameleon.Verify(hk, blobPrime, rPrime, digest))
}
