// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"github.com/ava-labs/libevm/rlp"

	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/snow/validators"
	"github.com/ava-labs/avalanchego/utils/crypto/bls"
	"github.com/ava-labs/avalanchego/vms/platformvm/warp"
)

// StateProof is the committee's aggregated BLS signature over a StateProposal,
// i.e. the proof that the redaction was approved.
type StateProof struct {
	Proposal     StateProposal
	SignerBitSet []byte
	AggSignature [bls.SignatureLen]byte
}

// Bytes is the RLP stored in the proof DB.
func (p *StateProof) Bytes() ([]byte, error) {
	return rlp.EncodeToBytes(p)
}

// StateProofFromBytes decodes what Bytes produced.
func StateProofFromBytes(b []byte) (*StateProof, error) {
	p := new(StateProof)
	if err := rlp.DecodeBytes(b, p); err != nil {
		return nil, err
	}
	return p, nil
}

// VerifyStateProof rebuilds the signed message from the proposal and checks the
// aggregated signature reaches the stake quorum.
func VerifyStateProof(
	proof *StateProof,
	networkID uint32,
	sourceChainID ids.ID,
	vdrs validators.WarpSet,
	quorumNum uint64,
	quorumDen uint64,
) error {
	msg, err := warp.NewUnsignedMessage(networkID, sourceChainID, proof.Proposal.Bytes())
	if err != nil {
		return err
	}
	sig := &warp.BitSetSignature{
		Signers:   proof.SignerBitSet,
		Signature: proof.AggSignature,
	}
	return sig.Verify(msg, networkID, vdrs, quorumNum, quorumDen)
}
