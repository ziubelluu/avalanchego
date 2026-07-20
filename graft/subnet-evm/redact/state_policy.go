// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"context"

	"github.com/ava-labs/libevm/ethdb"

	"github.com/ava-labs/avalanchego/ids"
)

// StateApprover says whether a redaction (a StateProposal) was approved by the
// committee. The forge needs this: no approval, no collision.
type StateApprover interface {
	ApprovedState(ctx context.Context, sp *StateProposal) bool
}

// committeeStatePolicy approves a redaction only if a stored proof for that exact
// proposal reaches the quorum.
type committeeStatePolicy struct {
	proofDB       ethdb.KeyValueReader
	warpSet       WarpSetFunc
	networkID     uint32
	sourceChainID ids.ID
	quorumNum     uint64
	quorumDen     uint64
}

// NewCommitteeStatePolicy builds the real approver (reads the proof from the DB).
func NewCommitteeStatePolicy(
	proofDB ethdb.KeyValueReader,
	warpSet WarpSetFunc,
	networkID uint32,
	sourceChainID ids.ID,
	quorumNum uint64,
	quorumDen uint64,
) StateApprover {
	return &committeeStatePolicy{
		proofDB:       proofDB,
		warpSet:       warpSet,
		networkID:     networkID,
		sourceChainID: sourceChainID,
		quorumNum:     quorumNum,
		quorumDen:     quorumDen,
	}
}

func (p *committeeStatePolicy) ApprovedState(ctx context.Context, sp *StateProposal) bool {
	proposalHash := sp.Hash()

	raw, err := ReadStateRedactionProof(p.proofDB, proposalHash)
	if err != nil {
		return false
	}
	proof, err := StateProofFromBytes(raw)
	if err != nil {
		return false
	}

	// Make sure the proof is for this exact proposal (no replay on another one).
	if proof.Proposal.Hash() != proposalHash {
		return false
	}

	ws, err := p.warpSet(ctx, sp.PChainHeight)
	if err != nil {
		return false
	}
	return VerifyStateProof(proof, p.networkID, p.sourceChainID, ws, p.quorumNum, p.quorumDen) == nil
}
