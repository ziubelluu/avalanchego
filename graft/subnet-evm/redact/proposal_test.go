// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"testing"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/rlp"
	"github.com/stretchr/testify/require"
)

func sampleProposal() *Proposal {
	return &Proposal{
		OriginalHash:    common.Hash{0x01},
		NewTxHash:       common.Hash{0x02},
		PChainHeight:    42,
		RedactedIndices: []uint64{0},
	}
}

func TestProposalHashDeterministic(t *testing.T) {
	t.Parallel()
	require.Equal(t, sampleProposal().Hash(), sampleProposal().Hash())
}

// Changing any field changes the hash.
func TestProposalHashChangesPerField(t *testing.T) {
	t.Parallel()

	base := sampleProposal().Hash()

	p1 := sampleProposal()
	p1.OriginalHash = common.Hash{0x09}
	require.NotEqual(t, base, p1.Hash())

	p2 := sampleProposal()
	p2.NewTxHash = common.Hash{0x09}
	require.NotEqual(t, base, p2.Hash())

	p3 := sampleProposal()
	p3.PChainHeight = 43
	require.NotEqual(t, base, p3.Hash())

	p4 := sampleProposal()
	p4.RedactedIndices = []uint64{0, 1}
	require.NotEqual(t, base, p4.Hash())
}

// Bytes round-trip back to the same proposal.
func TestProposalRoundTrip(t *testing.T) {
	t.Parallel()

	want := sampleProposal()
	got := new(Proposal)
	require.NoError(t, rlp.DecodeBytes(want.Bytes(), got))
	require.Equal(t, want, got)
}
