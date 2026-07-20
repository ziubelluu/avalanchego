// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"bytes"
	"testing"

	"github.com/ava-labs/libevm/common"
	"github.com/stretchr/testify/require"
)

func TestProposalFromBytesRoundTrip(t *testing.T) {
	p := &Proposal{
		OriginalHash:    common.Hash{0x01},
		NewTxHash:       common.Hash{0x02},
		PChainHeight:    9,
		RedactedIndices: []uint64{0, 2},
	}
	got, err := ProposalFromBytes(p.Bytes())
	require.NoError(t, err)
	require.Equal(t, *p, *got)

	_, err = ProposalFromBytes([]byte{0xff, 0xff})
	require.Error(t, err)
}

func TestStateProposalFromBytesRoundTrip(t *testing.T) {
	p := &StateProposal{
		OriginalHash: common.Hash{0x01},
		DepositAddr:  common.Address{0x0a},
		ID:           common.Hash{0x02},
		Digest:       bytes.Repeat([]byte{0x03}, 48),
		NewBlobHash:  common.Hash{0x04},
		PChainHeight: 7,
	}
	got, err := StateProposalFromBytes(p.Bytes())
	require.NoError(t, err)
	require.Equal(t, *p, *got)

	_, err = StateProposalFromBytes([]byte{0xff, 0xff})
	require.Error(t, err)
}
