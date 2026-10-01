// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package evm

import (
	"context"
	"testing"
	"time"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core/types"
	"github.com/stretchr/testify/require"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact"
	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/snow/validators"
	"github.com/ava-labs/avalanchego/snow/validators/validatorstest"
	"github.com/ava-labs/avalanchego/utils/crypto/bls"
	"github.com/ava-labs/avalanchego/utils/crypto/bls/signer/localsigner"
	"github.com/ava-labs/avalanchego/utils/set"

	warpprecompile "github.com/ava-labs/avalanchego/graft/subnet-evm/precompile/contracts/warp"
	commonEng "github.com/ava-labs/avalanchego/snow/engine/common"
	avalancheWarp "github.com/ava-labs/avalanchego/vms/platformvm/warp"
)

// txProposalFor is a tx proposal that blanks the calldata of tx 0 of [block].
func txProposalFor(t *testing.T, block *types.Block, pChainHeight uint64) *redact.Proposal {
	t.Helper()
	newTxs := make([]*types.Transaction, len(block.Transactions()))
	copy(newTxs, block.Transactions())
	blanked, err := redact.RebuildTxWithData(newTxs[0], nil)
	require.NoError(t, err)
	newTxs[0] = blanked
	return &redact.Proposal{
		OriginalHash:    block.Hash(),
		NewTxHash:       redact.RedactBlock(block, newTxs).TxHash(),
		PChainHeight:    pChainHeight,
		RedactedIndices: []uint64{0},
	}
}

// warpMessage is the message the validators sign for a proposal.
func warpMessage(t *testing.T, vm *VM, proposalBytes []byte) *avalancheWarp.UnsignedMessage {
	t.Helper()
	msg, err := avalancheWarp.NewUnsignedMessage(vm.ctx.NetworkID, vm.ctx.ChainID, proposalBytes)
	require.NoError(t, err)
	return msg
}

// requireSignsOnly checks that the warp backend of the VM signs [approved] with
// the node's own key, and does not sign [other].
func requireSignsOnly(t *testing.T, vm *VM, approved, other *avalancheWarp.UnsignedMessage) {
	t.Helper()
	require := require.New(t)

	stored, err := vm.warpBackend.GetMessage(approved.ID())
	require.NoError(err)
	require.Equal(approved.Bytes(), stored.Bytes())

	sigBytes, err := vm.warpBackend.GetMessageSignature(context.Background(), approved)
	require.NoError(err)
	sig, err := bls.SignatureFromBytes(sigBytes)
	require.NoError(err)
	require.True(bls.Verify(vm.ctx.PublicKey, sig, approved.Bytes()), "the signature must be the node's, over the approved message")

	// The other message was never approved: no signature for it, and the one
	// we have is not valid for it.
	_, err = vm.warpBackend.GetMessageSignature(context.Background(), other)
	require.Error(err, "a proposal that was not approved must not be signed")
	_, err = vm.warpBackend.GetMessage(other.ID())
	require.Error(err)
	require.False(bls.Verify(vm.ctx.PublicKey, sig, other.Bytes()))
}

// TestApproveRedaction covers what a validator does when it says yes to a
// proposal: it only accepts well-formed proposals for blocks it has, and from
// then on its warp backend signs exactly that proposal.
func TestApproveRedaction(t *testing.T) {
	d := setupVMDeposit(t)
	vm := d.tvm.vm

	t.Run("tx proposal for a known block", func(t *testing.T) {
		p := txProposalFor(t, d.block, 1)
		msg := warpMessage(t, vm, p.Bytes())

		id, err := vm.ApproveRedaction(RedactKindTx, p.Bytes())
		require.NoError(t, err)
		require.Equal(t, common.Hash(msg.ID()), id, "the returned id is the warp message id")

		notApproved := txProposalFor(t, d.block, 2) // same block, another proposal
		requireSignsOnly(t, vm, msg, warpMessage(t, vm, notApproved.Bytes()))
	})

	t.Run("deposit proposal for a known block", func(t *testing.T) {
		sp := d.proposal([]byte{})
		msg := warpMessage(t, vm, sp.Bytes())

		id, err := vm.ApproveRedaction(RedactKindState, sp.Bytes())
		require.NoError(t, err)
		require.Equal(t, common.Hash(msg.ID()), id)

		notApproved := d.proposal([]byte("some other content"))
		requireSignsOnly(t, vm, msg, warpMessage(t, vm, notApproved.Bytes()))
	})

	t.Run("unknown block", func(t *testing.T) {
		p := txProposalFor(t, d.block, 3)
		p.OriginalHash = common.Hash{0xde, 0xad}
		_, err := vm.ApproveRedaction(RedactKindTx, p.Bytes())
		require.ErrorContains(t, err, "unknown block")

		sp := d.proposal([]byte{})
		sp.OriginalHash = common.Hash{0xbe, 0xef}
		_, err = vm.ApproveRedaction(RedactKindState, sp.Bytes())
		require.ErrorContains(t, err, "unknown block")

		// nothing was registered for them
		for _, b := range [][]byte{p.Bytes(), sp.Bytes()} {
			msg := warpMessage(t, vm, b)
			_, err := vm.warpBackend.GetMessage(msg.ID())
			require.Error(t, err, "no message must be stored for a refused proposal")
			_, err = vm.warpBackend.GetMessageSignature(context.Background(), msg)
			require.Error(t, err)
		}
	})

	t.Run("malformed proposal", func(t *testing.T) {
		garbage := []byte{0xff, 0xff}
		_, err := vm.ApproveRedaction(RedactKindTx, garbage)
		require.ErrorContains(t, err, "malformed tx proposal")
		_, err = vm.ApproveRedaction(RedactKindState, garbage)
		require.ErrorContains(t, err, "malformed state proposal")

		// a proposal of one kind is not a proposal of the other kind
		_, err = vm.ApproveRedaction(RedactKindState, txProposalFor(t, d.block, 4).Bytes())
		require.ErrorContains(t, err, "malformed state proposal")
	})

	t.Run("unknown kind", func(t *testing.T) {
		_, err := vm.ApproveRedaction("block", txProposalFor(t, d.block, 5).Bytes())
		require.ErrorContains(t, err, "unknown redaction kind")
	})
}

// selfValidator makes the VM the only validator of its subnet, with its own
// BLS key, and wires the test sender so that the signature requests the VM
// sends out come back to the VM itself, like avalanchego does for a node that
// messages itself. [others] are extra validators that never answer.
func selfValidator(t *testing.T, tvm *testVM, others ...*validators.GetValidatorOutput) validators.WarpSet {
	t.Helper()
	vm := tvm.vm

	vdrs := map[ids.NodeID]*validators.GetValidatorOutput{
		vm.ctx.NodeID: {NodeID: vm.ctx.NodeID, PublicKey: vm.ctx.PublicKey, Weight: 1},
	}
	for _, o := range others {
		vdrs[o.NodeID] = o
	}
	ws, err := validators.FlattenValidatorSet(vdrs)
	require.NoError(t, err)
	vm.ctx.ValidatorState = &validatorstest.State{
		GetWarpValidatorSetsF: func(context.Context, uint64) (map[ids.ID]validators.WarpSet, error) {
			return map[ids.ID]validators.WarpSet{vm.ctx.SubnetID: ws}, nil
		},
	}

	tvm.appSender.SendAppRequestF = func(_ context.Context, nodeIDs set.Set[ids.NodeID], requestID uint32, msg []byte) error {
		for nodeID := range nodeIDs {
			go func() {
				if nodeID == vm.ctx.NodeID {
					_ = vm.Network.AppRequest(context.Background(), nodeID, requestID, time.Now().Add(10*time.Second), msg)
					return
				}
				// the other validators are not there
				_ = vm.Network.AppRequestFailed(context.Background(), nodeID, requestID, &commonEng.AppError{Code: -1, Message: "unreachable"})
			}()
		}
		return nil
	}
	tvm.appSender.SendAppResponseF = func(_ context.Context, nodeID ids.NodeID, requestID uint32, response []byte) error {
		go func() { _ = vm.Network.AppResponse(context.Background(), nodeID, requestID, response) }()
		return nil
	}
	tvm.appSender.SendAppErrorF = func(_ context.Context, nodeID ids.NodeID, requestID uint32, code int32, msg string) error {
		go func() {
			_ = vm.Network.AppRequestFailed(context.Background(), nodeID, requestID, &commonEng.AppError{Code: code, Message: msg})
		}()
		return nil
	}
	return ws
}

// TestCollectRedactionProof: after the validator approved, collecting gives a
// proof of the right kind that reaches the quorum. Without the approval the
// validator does not sign and no usable proof comes out.
func TestCollectRedactionProof(t *testing.T) {
	d := setupVMDeposit(t)
	vm := d.tvm.vm
	ws := selfValidator(t, d.tvm)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("tx proposal", func(t *testing.T) {
		require := require.New(t)
		p := txProposalFor(t, d.block, 1)
		_, err := vm.ApproveRedaction(RedactKindTx, p.Bytes())
		require.NoError(err)

		raw, err := vm.CollectRedactionProof(ctx, RedactKindTx, p.Bytes())
		require.NoError(err)
		kind, err := redact.KindOf(raw)
		require.NoError(err)
		require.Equal(redact.KindTx, kind)

		proof, err := redact.ProofFromBytes(raw)
		require.NoError(err)
		require.Equal(*p, proof.Proposal)
		require.NoError(redact.VerifyRedactionProof(proof, vm.ctx.NetworkID, vm.ctx.ChainID, ws,
			warpprecompile.WarpDefaultQuorumNumerator, warpprecompile.WarpQuorumDenominator))

		// it's not a deposit proof
		_, err = redact.StateProofFromBytes(raw)
		require.Error(err)
	})

	t.Run("deposit proposal", func(t *testing.T) {
		require := require.New(t)
		sp := d.proposal([]byte{})
		_, err := vm.ApproveRedaction(RedactKindState, sp.Bytes())
		require.NoError(err)

		raw, err := vm.CollectRedactionProof(ctx, RedactKindState, sp.Bytes())
		require.NoError(err)
		kind, err := redact.KindOf(raw)
		require.NoError(err)
		require.Equal(redact.KindState, kind)

		proof, err := redact.StateProofFromBytes(raw)
		require.NoError(err)
		require.Equal(sp.Hash(), proof.Proposal.Hash())
		require.NoError(redact.VerifyStateProof(proof, vm.ctx.NetworkID, vm.ctx.ChainID, ws,
			warpprecompile.WarpDefaultQuorumNumerator, warpprecompile.WarpQuorumDenominator))
	})

	// Without the approval the validator refuses to sign. The collection does
	// not fail: it gives back a proof with no signers, which is below the
	// quorum and is refused by whoever verifies it.
	t.Run("without approval", func(t *testing.T) {
		require := require.New(t)
		p := txProposalFor(t, d.block, 7) // never approved
		_, err := vm.CollectRedactionProof(ctx, RedactKindTx, p.Bytes())
		require.ErrorIs(err, errProofBelowQuorum, "nobody signed, there is no proof to give back")

		sp := d.proposal([]byte("never approved"))
		_, err = vm.CollectRedactionProof(ctx, RedactKindState, sp.Bytes())
		require.ErrorIs(err, errProofBelowQuorum)
	})

	t.Run("unknown kind", func(t *testing.T) {
		_, err := vm.CollectRedactionProof(ctx, "block", txProposalFor(t, d.block, 8).Bytes())
		require.ErrorContains(t, err, "unknown redaction kind")
		_, err = vm.CollectRedactionProof(ctx, RedactKindTx, []byte{0xff, 0xff})
		require.ErrorContains(t, err, "malformed tx proposal")
	})

	// Two validators with the same weight, only this node approves and the
	// other one is not reachable: one signature out of two is 50%, below the
	// 67% quorum, so the collection fails.
	t.Run("one of two validators", func(t *testing.T) {
		require := require.New(t)
		otherKey, err := localsigner.New()
		require.NoError(err)
		ws2 := selfValidator(t, d.tvm, &validators.GetValidatorOutput{
			NodeID: ids.GenerateTestNodeID(), PublicKey: otherKey.PublicKey(), Weight: 1,
		})
		require.Len(ws2.Validators, 2)

		p := txProposalFor(t, d.block, 9)
		_, err = vm.ApproveRedaction(RedactKindTx, p.Bytes())
		require.NoError(err)

		_, err = vm.CollectRedactionProof(ctx, RedactKindTx, p.Bytes())
		require.ErrorIs(err, errProofBelowQuorum)
	})
}
