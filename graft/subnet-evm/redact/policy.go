// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"context"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/ethdb"

	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/snow/validators"

	ethtypes "github.com/ava-labs/libevm/core/types"
)

// WarpSetFunc returns the subnet validator set at a P-Chain height. The VM
// builds it from ctx.ValidatorState, so this package doesn't need snow.Context.
type WarpSetFunc func(ctx context.Context, pChainHeight uint64) (validators.WarpSet, error)

// committeePolicy approves a redaction only if a stored proof verifies against
// the validator set quorum and is bound to this exact block and body.
type committeePolicy struct {
	proofDB       ethdb.KeyValueReader
	warpSet       WarpSetFunc
	networkID     uint32
	sourceChainID ids.ID
	quorumNum     uint64
	quorumDen     uint64
}

// NewCommitteePolicy builds the real redaction policy.
func NewCommitteePolicy(
	proofDB ethdb.KeyValueReader,
	warpSet WarpSetFunc,
	networkID uint32,
	sourceChainID ids.ID,
	quorumNum uint64,
	quorumDen uint64,
) Policy {
	return &committeePolicy{
		proofDB:       proofDB,
		warpSet:       warpSet,
		networkID:     networkID,
		sourceChainID: sourceChainID,
		quorumNum:     quorumNum,
		quorumDen:     quorumDen,
	}
}

func (p *committeePolicy) Approved(ctx context.Context, parent *ethtypes.Header) bool {
	// The old link is the original hash H0 the proof is keyed by.
	originalHash := OldLink(parent)

	raw, err := ReadRedactionProof(p.proofDB, originalHash)
	if err != nil {
		return false
	}
	kind, err := KindOf(raw)
	if err != nil {
		return false
	}
	switch kind {
	case KindTx:
		return p.approvedTx(ctx, raw, originalHash, parent)
	case KindState:
		return p.approvedState(ctx, raw, originalHash)
	default:
		return false
	}
}

// approvedTx: the proof is for this block, for the body that is actually
// there, and reaches the quorum.
func (p *committeePolicy) approvedTx(ctx context.Context, raw []byte, originalHash common.Hash, parent *ethtypes.Header) bool {
	proof, err := ProofFromBytes(raw)
	if err != nil {
		return false
	}

	// Bind the proof to this block and to the body actually present, so a proof
	// approving one body cannot be replayed for another.
	if proof.Proposal.OriginalHash != originalHash {
		return false
	}
	if proof.Proposal.NewTxHash != parent.TxHash {
		return false
	}

	ws, err := p.warpSet(ctx, proof.Proposal.PChainHeight)
	if err != nil {
		return false
	}
	return VerifyRedactionProof(proof, p.networkID, p.sourceChainID, ws, p.quorumNum, p.quorumDen) == nil
}

// approvedState: the proof is for this block and reaches the quorum. A
// StateProposal has no NewTxHash (the new opening depends on the random k of
// the forge), so the link between proof and body is checked where the body
// is, by the content verifier.
func (p *committeePolicy) approvedState(ctx context.Context, raw []byte, originalHash common.Hash) bool {
	proof, err := StateProofFromBytes(raw)
	if err != nil {
		return false
	}
	if proof.Proposal.OriginalHash != originalHash {
		return false
	}

	ws, err := p.warpSet(ctx, proof.Proposal.PChainHeight)
	if err != nil {
		return false
	}
	return VerifyStateProof(proof, p.networkID, p.sourceChainID, ws, p.quorumNum, p.quorumDen) == nil
}
