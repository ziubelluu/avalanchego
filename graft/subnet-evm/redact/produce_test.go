// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ava-labs/avalanchego/network/p2p/acp118"
	"github.com/ava-labs/avalanchego/snow/validators"
	"github.com/ava-labs/avalanchego/utils/constants"
	"github.com/ava-labs/avalanchego/utils/crypto/bls"
	"github.com/ava-labs/avalanchego/utils/set"
	"github.com/ava-labs/avalanchego/vms/platformvm/warp"
)

// The real aggregator must satisfy our interface.
var _ Aggregator = (*acp118.SignatureAggregator)(nil)

// fakeAggregator signs locally with a chosen subset of the committee instead of
// going over the network.
type fakeAggregator struct {
	byIndex  map[int]bls.Signer
	signWith []int
	err      error
}

func (f *fakeAggregator) AggregateSignatures(
	_ context.Context,
	message *warp.Message,
	_ []byte,
	_ []*validators.Warp,
	_ uint64,
	_ uint64,
) (*warp.Message, *big.Int, *big.Int, error) {
	if f.err != nil {
		return nil, nil, nil, f.err
	}
	msgBytes := message.UnsignedMessage.Bytes()
	signers := set.NewBits()
	sigs := make([]*bls.Signature, 0, len(f.signWith))
	for _, idx := range f.signWith {
		sig, err := f.byIndex[idx].Sign(msgBytes)
		if err != nil {
			return nil, nil, nil, err
		}
		sigs = append(sigs, sig)
		signers.Add(idx)
	}
	aggSig, err := bls.AggregateSignatures(sigs)
	if err != nil {
		return nil, nil, nil, err
	}
	var aggBytes [bls.SignatureLen]byte
	copy(aggBytes[:], bls.SignatureToBytes(aggSig))
	signed := &warp.Message{
		UnsignedMessage: message.UnsignedMessage,
		Signature:       &warp.BitSetSignature{Signers: signers.Bytes(), Signature: aggBytes},
	}
	return signed, big.NewInt(0), big.NewInt(0), nil
}

// A produced proof verifies against the same committee and quorum.
func TestProduceProofVerifies(t *testing.T) {
	t.Parallel()

	ws, byIndex := makeCommittee(t, 3)
	agg := &fakeAggregator{byIndex: byIndex, signWith: []int{0, 1, 2}}
	proposal := sampleProposal()

	proof, err := ProduceProof(context.Background(), agg, proposal, constants.UnitTestID, proofSourceChainID, ws, 2, 3)
	require.NoError(t, err)
	require.Equal(t, *proposal, proof.Proposal)
	require.NoError(t, VerifyRedactionProof(proof, constants.UnitTestID, proofSourceChainID, ws, 2, 3))
}

// An aggregator error is propagated.
func TestProduceProofAggregatorError(t *testing.T) {
	t.Parallel()

	ws, byIndex := makeCommittee(t, 3)
	agg := &fakeAggregator{byIndex: byIndex, err: errors.New("not enough stake")}

	_, err := ProduceProof(context.Background(), agg, sampleProposal(), constants.UnitTestID, proofSourceChainID, ws, 2, 3)
	require.Error(t, err)
}
