// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/crypto"
	"github.com/ava-labs/libevm/rlp"
)

// StateProposal is what the committee votes on to redact data stored in state.
// Unlike the tx-channel Proposal, it does NOT fix the new tx hash: the forged r'
// (and so the new tx hash) depends on the secret trapdoor, so the committee can't
// know it beforehand. What it pins is the digest D in state: any replacement must
// still satisfy CH(newBlob, r') == D.
type StateProposal struct {
	OriginalHash common.Hash    // block that holds the (blob, r) in its calldata
	DepositAddr  common.Address // the deposit contract that committed the digest
	ID           common.Hash    // the deposit id
	Digest       []byte         // the committed digest D (doesn't change on redaction)
	NewBlobHash  common.Hash    // keccak256 of the approved new blob (e.g. empty)
	PChainHeight uint64         // which validator set to check the proof against
}

// Bytes is the RLP that validators sign.
func (p *StateProposal) Bytes() []byte {
	b, err := rlp.EncodeToBytes(p)
	if err != nil {
		panic(err)
	}
	return b
}

// StateProposalFromBytes decodes what Bytes produced.
func StateProposalFromBytes(b []byte) (*StateProposal, error) {
	p := new(StateProposal)
	if err := rlp.DecodeBytes(b, p); err != nil {
		return nil, err
	}
	return p, nil
}

// Hash is keccak256(Bytes): it keys the stored proof and identifies the vote.
func (p *StateProposal) Hash() common.Hash {
	return crypto.Keccak256Hash(p.Bytes())
}
