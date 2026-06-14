// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/snow/validators"
	"github.com/ava-labs/avalanchego/vms/platformvm/warp"
)

// Aggregator collects BLS signatures from the validators over a Warp message
// until the stake quorum is reached. Its signature matches
// acp118.SignatureAggregator.AggregateSignatures, so the real one satisfies it
// and tests can use a fake.
type Aggregator interface {
	AggregateSignatures(
		ctx context.Context,
		message *warp.Message,
		justification []byte,
		validators []*validators.Warp,
		quorumNum uint64,
		quorumDen uint64,
	) (*warp.Message, *big.Int, *big.Int, error)
}

// ProduceProof asks the committee to sign the proposal and packs the aggregated
// signature into a Proof ready to be stored.
func ProduceProof(
	ctx context.Context,
	agg Aggregator,
	proposal *Proposal,
	networkID uint32,
	sourceChainID ids.ID,
	vdrs validators.WarpSet,
	quorumNum uint64,
	quorumDen uint64,
) (*Proof, error) {
	unsigned, err := warp.NewUnsignedMessage(networkID, sourceChainID, proposal.Bytes())
	if err != nil {
		return nil, err
	}
	msg := &warp.Message{
		UnsignedMessage: *unsigned,
		Signature:       &warp.BitSetSignature{},
	}

	signed, _, _, err := agg.AggregateSignatures(ctx, msg, nil, vdrs.Validators, quorumNum, quorumDen)
	if err != nil {
		return nil, err
	}

	bss, ok := signed.Signature.(*warp.BitSetSignature)
	if !ok {
		return nil, fmt.Errorf("unexpected signature type %T", signed.Signature)
	}

	return &Proof{
		Proposal:     *proposal,
		SignerBitSet: bss.Signers,
		AggSignature: bss.Signature,
	}, nil
}
