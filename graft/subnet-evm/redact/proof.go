// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"errors"

	"github.com/ava-labs/libevm/rlp"

	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/snow/validators"
	"github.com/ava-labs/avalanchego/utils/crypto/bls"
	"github.com/ava-labs/avalanchego/vms/platformvm/warp"
)

// errMalformedRedactedIndices is returned when a proof's redacted indices are
// not strictly increasing (i.e. not sorted, or contain duplicates).
var errMalformedRedactedIndices = errors.New("redacted indices must be strictly increasing")

// Proof is the evidence a redaction was approved: the proposal plus the
// committee's aggregated BLS signature over it.
type Proof struct {
	Proposal     Proposal
	SignerBitSet []byte
	AggSignature [bls.SignatureLen]byte
}

// Bytes is the kind byte followed by the RLP encoding. This is what goes in
// the proof DB and over the RPC.
func (p *Proof) Bytes() ([]byte, error) {
	body, err := rlp.EncodeToBytes(p)
	if err != nil {
		return nil, err
	}
	return withKind(KindTx, body), nil
}

// ProofFromBytes decodes a proof produced by Bytes. Bytes of a StateProof
// are refused.
func ProofFromBytes(b []byte) (*Proof, error) {
	body, err := stripKind(KindTx, b)
	if err != nil {
		return nil, err
	}
	p := new(Proof)
	if err := rlp.DecodeBytes(body, p); err != nil {
		return nil, err
	}
	return p, nil
}

// VerifyRedactionProof rebuilds the signed message from the proposal and checks
// the aggregated signature reaches the stake quorum over the validator set.
func VerifyRedactionProof(
	proof *Proof,
	networkID uint32,
	sourceChainID ids.ID,
	vdrs validators.WarpSet,
	quorumNum uint64,
	quorumDen uint64,
) error {
	if !indicesStrictlyIncreasing(proof.Proposal.RedactedIndices) {
		return errMalformedRedactedIndices
	}
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

// indicesStrictlyIncreasing reports whether idx is sorted ascending with no
// duplicates (the canonical, well-formed shape produced by the redactor).
func indicesStrictlyIncreasing(idx []uint64) bool {
	for i := 1; i < len(idx); i++ {
		if idx[i] <= idx[i-1] {
			return false
		}
	}
	return true
}
