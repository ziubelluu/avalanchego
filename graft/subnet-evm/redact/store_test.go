// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"testing"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core/rawdb"
	"github.com/stretchr/testify/require"
)

// Write then read gives back the same bytes; Has reflects presence.
func TestRedactionProofWriteRead(t *testing.T) {
	t.Parallel()

	db := rawdb.NewMemoryDatabase()
	h := common.Hash{0x01}
	proof := []byte("aggregated-bls-proof")

	has, err := HasRedactionProof(db, h)
	require.NoError(t, err)
	require.False(t, has)

	require.NoError(t, WriteRedactionProof(db, h, proof))

	has, err = HasRedactionProof(db, h)
	require.NoError(t, err)
	require.True(t, has)

	got, err := ReadRedactionProof(db, h)
	require.NoError(t, err)
	require.Equal(t, proof, got)
}

// Proofs are keyed per block: a different hash has no proof.
func TestRedactionProofPerBlock(t *testing.T) {
	t.Parallel()

	db := rawdb.NewMemoryDatabase()
	require.NoError(t, WriteRedactionProof(db, common.Hash{0x01}, []byte("p")))

	has, err := HasRedactionProof(db, common.Hash{0x02})
	require.NoError(t, err)
	require.False(t, has)
}

// Delete removes the proof.
func TestRedactionProofDelete(t *testing.T) {
	t.Parallel()

	db := rawdb.NewMemoryDatabase()
	h := common.Hash{0x01}
	require.NoError(t, WriteRedactionProof(db, h, []byte("p")))
	require.NoError(t, DeleteRedactionProof(db, h))

	has, err := HasRedactionProof(db, h)
	require.NoError(t, err)
	require.False(t, has)
}
