// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package evm

import (
	"context"
	"errors"
	"fmt"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core/types"
	"github.com/ava-labs/libevm/crypto"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact/redactabledeposit"
	warpprecompile "github.com/ava-labs/avalanchego/graft/subnet-evm/precompile/contracts/warp"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact"
	"github.com/ava-labs/avalanchego/network/p2p"
	"github.com/ava-labs/avalanchego/network/p2p/acp118"

	avalancheWarp "github.com/ava-labs/avalanchego/vms/platformvm/warp"
)

// Redaction proposal kinds for ApproveRedaction.
const (
	RedactKindTx    = "tx"    // tx-channel (old/new-link) redaction proposal
	RedactKindState = "state" // chameleon state-data redaction proposal
)

// RedactTrapdoorEnvVar is the env var with the authority trapdoor (hex). Only the
// authority's node sets it; without it RedactStateDeposit can't forge.
const RedactTrapdoorEnvVar = "SUBNET_EVM_REDACT_TRAPDOOR"

// RedactStateDeposit does a state-data redaction end-to-end on a running node:
// builds the proposal, stores the committee proof, forges r' for newBlob (only if
// the vote passed), rewrites the store tx with the new (blob', r') and applies it
// via RedactStored. The digest in state and the roots don't change. Returns the
// redacted block hash and r'.
func (vm *VM) RedactStateDeposit(
	ctx context.Context,
	originalHash common.Hash,
	depositAddr common.Address,
	id common.Hash,
	blob, randomness, newBlob, proofBytes []byte,
	pChainHeight uint64,
) (common.Hash, []byte, error) {
	bc := vm.blockChain
	original := bc.GetBlockByHash(originalHash)
	if original == nil {
		return common.Hash{}, nil, errors.New("original block not found")
	}
	origTx, ok := redactabledeposit.FindStoreTx(original, depositAddr, id)
	if !ok {
		return common.Hash{}, nil, errors.New("store tx for id not found in block")
	}

	statedb, err := bc.State()
	if err != nil {
		return common.Hash{}, nil, err
	}
	digest := redactabledeposit.GetDigest(statedb, depositAddr, id)
	if digest == nil {
		return common.Hash{}, nil, errors.New("no digest committed for id")
	}

	sp := &redact.StateProposal{
		OriginalHash: originalHash,
		DepositAddr:  depositAddr,
		ID:           id,
		Digest:       digest,
		NewBlobHash:  crypto.Keccak256Hash(newBlob),
		PChainHeight: pChainHeight,
	}
	if err := redact.WriteStateRedactionProof(vm.chaindb, sp.Hash(), proofBytes); err != nil {
		return common.Hash{}, nil, err
	}

	approver := redact.NewCommitteeStatePolicy(
		vm.chaindb,
		redact.NewWarpSetFunc(vm.ctx.ValidatorState, vm.ctx.SubnetID),
		vm.ctx.NetworkID,
		vm.ctx.ChainID,
		warpprecompile.WarpDefaultQuorumNumerator,
		warpprecompile.WarpQuorumDenominator,
	)
	forger, err := redact.NewForgerFromEnv(approver, RedactTrapdoorEnvVar)
	if err != nil {
		return common.Hash{}, nil, err
	}

	rPrime, err := forger.Forge(ctx, sp, blob, randomness, newBlob)
	if err != nil {
		return common.Hash{}, nil, err
	}

	redactedTx, err := redactabledeposit.RebuildRedactedStoreTx(origTx, newBlob, rPrime)
	if err != nil {
		return common.Hash{}, nil, err
	}

	newTxs := make([]*types.Transaction, len(original.Transactions()))
	for i, tx := range original.Transactions() {
		if tx.Hash() == origTx.Hash() {
			newTxs[i] = redactedTx
		} else {
			newTxs[i] = tx
		}
	}

	redacted, err := bc.RedactStored(original, newTxs, proofBytes)
	if err != nil {
		return common.Hash{}, nil, err
	}
	return redacted.Hash(), rPrime, nil
}

// RedactTransactions does a tx-channel (old/new-link) redaction on a running
// node: it blanks the calldata of the positions the committee approved, checks
// the new body matches the signed NewTxHash and that the proof reaches quorum,
// then applies it. Roots don't change. Returns the redacted block hash.
func (vm *VM) RedactTransactions(ctx context.Context, originalHash common.Hash, proofBytes []byte) (common.Hash, error) {
	bc := vm.blockChain
	original := bc.GetBlockByHash(originalHash)
	if original == nil {
		return common.Hash{}, errors.New("original block not found")
	}

	proof, err := redact.ProofFromBytes(proofBytes)
	if err != nil {
		return common.Hash{}, err
	}
	if proof.Proposal.OriginalHash != originalHash {
		return common.Hash{}, errors.New("proof is not bound to this block")
	}

	redactedIndex := make(map[uint64]bool, len(proof.Proposal.RedactedIndices))
	for _, i := range proof.Proposal.RedactedIndices {
		redactedIndex[i] = true
	}

	txs := original.Transactions()
	newTxs := make([]*types.Transaction, len(txs))
	for i, tx := range txs {
		if !redactedIndex[uint64(i)] {
			newTxs[i] = tx
			continue
		}
		rebuilt, err := redact.RebuildTxWithData(tx, nil)
		if err != nil {
			return common.Hash{}, err
		}
		newTxs[i] = rebuilt
	}

	// The new body must be exactly the one the committee signed.
	redacted := redact.RedactBlock(original, newTxs)
	if redacted.TxHash() != proof.Proposal.NewTxHash {
		return common.Hash{}, errors.New("redacted body does not match the approved NewTxHash")
	}

	// And the proof must reach the quorum before we apply.
	ws, err := redact.NewWarpSetFunc(vm.ctx.ValidatorState, vm.ctx.SubnetID)(ctx, proof.Proposal.PChainHeight)
	if err != nil {
		return common.Hash{}, err
	}
	if err := redact.VerifyRedactionProof(
		proof,
		vm.ctx.NetworkID,
		vm.ctx.ChainID,
		ws,
		warpprecompile.WarpDefaultQuorumNumerator,
		warpprecompile.WarpQuorumDenominator,
	); err != nil {
		return common.Hash{}, err
	}

	applied, err := bc.RedactStored(original, newTxs, proofBytes)
	if err != nil {
		return common.Hash{}, err
	}
	return applied.Hash(), nil
}

// ApproveRedaction is how this validator says "yes" to a redaction proposal: it
// decodes and sanity-checks the proposal, then adds it to the warp backend so the
// node will sign exactly that proposal when the aggregator asks. Returns the warp
// message id the committee aggregates over. It's tied to the exact proposal, not
// a blanket OK.
func (vm *VM) ApproveRedaction(kind string, proposalBytes []byte) (common.Hash, error) {
	var originalHash common.Hash
	switch kind {
	case RedactKindTx:
		p, err := redact.ProposalFromBytes(proposalBytes)
		if err != nil {
			return common.Hash{}, fmt.Errorf("malformed tx proposal: %w", err)
		}
		originalHash = p.OriginalHash
	case RedactKindState:
		p, err := redact.StateProposalFromBytes(proposalBytes)
		if err != nil {
			return common.Hash{}, fmt.Errorf("malformed state proposal: %w", err)
		}
		originalHash = p.OriginalHash
	default:
		return common.Hash{}, fmt.Errorf("unknown redaction kind %q", kind)
	}

	// Only approve if this node actually has the target block.
	if vm.blockChain.GetBlockByHash(originalHash) == nil {
		return common.Hash{}, errors.New("proposal targets an unknown block")
	}

	msg, err := avalancheWarp.NewUnsignedMessage(vm.ctx.NetworkID, vm.ctx.ChainID, proposalBytes)
	if err != nil {
		return common.Hash{}, err
	}
	if err := vm.warpBackend.AddMessage(msg); err != nil {
		return common.Hash{}, err
	}
	return common.Hash(msg.ID()), nil
}

// CollectRedactionProof gathers the committee signatures (via the warp
// aggregator) into a Proof (tx) or StateProof (state) that reaches the quorum.
// The bytes are ready for RedactTransactions / RedactStateDeposit. Validators
// only sign proposals they approved (see ApproveRedaction).
func (vm *VM) CollectRedactionProof(ctx context.Context, kind string, proposalBytes []byte) ([]byte, error) {
	// Decode once to get the proposal type and its PChainHeight.
	var (
		txProposal    *redact.Proposal
		stateProposal *redact.StateProposal
		pChainHeight  uint64
	)
	switch kind {
	case RedactKindTx:
		p, err := redact.ProposalFromBytes(proposalBytes)
		if err != nil {
			return nil, fmt.Errorf("malformed tx proposal: %w", err)
		}
		txProposal, pChainHeight = p, p.PChainHeight
	case RedactKindState:
		p, err := redact.StateProposalFromBytes(proposalBytes)
		if err != nil {
			return nil, fmt.Errorf("malformed state proposal: %w", err)
		}
		stateProposal, pChainHeight = p, p.PChainHeight
	default:
		return nil, fmt.Errorf("unknown redaction kind %q", kind)
	}

	ws, err := redact.NewWarpSetFunc(vm.ctx.ValidatorState, vm.ctx.SubnetID)(ctx, pChainHeight)
	if err != nil {
		return nil, err
	}

	warpSDKClient := vm.P2PNetwork().NewClient(p2p.SignatureRequestHandlerID, vm.P2PValidators())
	aggregator := acp118.NewSignatureAggregator(vm.ctx.Log, warpSDKClient)

	if txProposal != nil {
		proof, err := redact.ProduceProof(ctx, aggregator, txProposal, vm.ctx.NetworkID, vm.ctx.ChainID, ws,
			warpprecompile.WarpDefaultQuorumNumerator, warpprecompile.WarpQuorumDenominator)
		if err != nil {
			return nil, err
		}
		return proof.Bytes()
	}
	proof, err := redact.ProduceStateProof(ctx, aggregator, stateProposal, vm.ctx.NetworkID, vm.ctx.ChainID, ws,
		warpprecompile.WarpDefaultQuorumNumerator, warpprecompile.WarpQuorumDenominator)
	if err != nil {
		return nil, err
	}
	return proof.Bytes()
}
