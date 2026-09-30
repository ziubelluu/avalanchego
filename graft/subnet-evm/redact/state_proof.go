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

// Bytes is the kind byte followed by the RLP encoding. This is what goes in
// the proof DB and over the RPC.
func (p *StateProof) Bytes() ([]byte, error) {
	body, err := rlp.EncodeToBytes(p)
	if err != nil {
		return nil, err
	}
	return withKind(KindState, body), nil
}

// StateProofFromBytes decodes what Bytes produced. Bytes of a Proof are
// refused.
func StateProofFromBytes(b []byte) (*StateProof, error) {
	body, err := stripKind(KindState, b)
	if err != nil {
		return nil, err
	}
	p := new(StateProof)
	if err := rlp.DecodeBytes(body, p); err != nil {
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
