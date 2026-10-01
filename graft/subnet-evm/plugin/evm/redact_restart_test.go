// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package evm

import (
	"bytes"
	"context"
	"testing"

	"github.com/ava-labs/libevm/common"
	"github.com/stretchr/testify/require"

	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/vms/components/chain"
)

// TestRedactedTipKeepsItsIDAcrossRestart: the tip of the chain gets redacted
// and the node restarts. For the engine the block is still the one it
// accepted, so the VM has to keep answering with the original ID: before the
// restart, after it, and when a peer sends the original bytes again. Then the
// chain has to go on from there.
func TestRedactedTipKeepsItsIDAcrossRestart(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()
	d := setupVMDeposit(t)
	vm := d.tvm.vm

	origID := ids.ID(d.block.Hash())
	before, err := vm.GetBlock(ctx, origID)
	require.NoError(err)
	originalBytes := bytes.Clone(before.Bytes())
	require.True(bytes.Contains(originalBytes, d.blob), "the deposit block carries the blob")
	last, err := vm.LastAccepted(ctx)
	require.NoError(err)
	require.Equal(origID, last, "the deposit block is the tip")

	// redact the tip
	blobPrime := []byte{}
	proof := d.committee.signState(t, vm, d.proposal(blobPrime), 0, 1, 2)
	_, _, err = vm.RedactStateDeposit(ctx, d.block.Hash(), d.depositAddr, d.id, d.blob, d.r, blobPrime, proof, 1)
	require.NoError(err)

	// check is what the engine sees of the tip
	check := func(vm *VM, when string) {
		last, err := vm.LastAccepted(ctx)
		require.NoError(err, when)
		require.Equal(origID, last, "%s: the last accepted block keeps its ID", when)

		blk, err := vm.GetBlock(ctx, origID)
		require.NoError(err, when)
		require.Equal(origID, blk.ID(), "%s: the block is found by its original ID and answers with it", when)
		require.False(bytes.Contains(blk.Bytes(), d.blob), "%s: the VM must not hand out the blob anymore", when)

		require.NoError(vm.SetPreference(ctx, origID), when)

		// a peer that did not redact still has the original bytes
		parsed, err := vm.ParseBlock(ctx, originalBytes)
		require.NoError(err, when)
		require.Equal(origID, parsed.ID(), when)
		require.NoError(vm.SetPreference(ctx, parsed.ID()), "%s: the original bytes must not look like a fork", when)
	}
	check(vm, "after the redaction")

	// restart
	restarted, err := restartVM(d.tvm, d.tvm.config)
	require.NoError(err)
	d.tvm.vm = restarted.vm // so the cleanup shuts down the running VM
	vm = restarted.vm
	check(vm, "after the restart")

	// the chain goes on: a new block on top of the redacted tip
	to := common.Address{0x99}
	next := sendAndAccept(t, vm, 2, &to, 30_000, nil)
	require.Equal(common.Hash(origID), next.ParentHash())
	nextWrapped, err := vm.GetBlock(ctx, ids.ID(next.Hash()))
	require.NoError(err)
	require.Equal(origID, nextWrapped.(*chain.BlockWrapper).Parent())

	// and one more, so the tx pool has to have followed the redacted head
	after := sendAndAccept(t, vm, 3, &to, 30_000, nil)
	require.Equal(next.Hash(), after.ParentHash())
	require.NoError(vm.blockChain.ValidateCanonicalChain())
}
