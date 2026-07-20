// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redactabledeposit_test

import (
	"bytes"
	"context"
	"math/big"
	"testing"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core/types"
	"github.com/ava-labs/libevm/crypto"
	"github.com/ava-labs/libevm/trie"
	"github.com/stretchr/testify/require"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact/redactabledeposit"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact/chameleon"
)

// stubApprover is a committee approver whose outcome is fixed, so the test can
// drive the vote-gate deterministically.
type stubApprover struct{ approve bool }

func (p stubApprover) ApprovedState(context.Context, *redact.StateProposal) bool { return p.approve }

// TestApplyOffStateRedaction: after an approved vote we forge r', swap (blob, r)
// for ("", r') and apply it with RedactBlock; the digest and the roots stay put.
func TestApplyOffStateRedaction(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	// Deposit material: digest D = CH(blob, r) committed in state.
	hk, tk, err := chameleon.KeyGen()
	require.NoError(err)
	blob := bytes.Repeat([]byte{0xAB, 0xCD, 0xEF, 0x12}, 256)
	r := bytes.Repeat([]byte{0x07}, 32)
	digest := chameleon.Hash(hk, blob, r)
	id := crypto.Keccak256Hash([]byte("deposit-1"))

	origCalldata, err := redactabledeposit.PackStore(id, blob, r, digest)
	require.NoError(err)

	// The vote-gated forge: produce r' for the empty replacement blob.
	blobPrime := []byte{}
	sp := &redact.StateProposal{NewBlobHash: crypto.Keccak256Hash(blobPrime)}
	forger := redact.NewForger(stubApprover{approve: true}, tk)
	rPrime, err := forger.Forge(ctx, sp, blob, r, blobPrime)
	require.NoError(err)

	// Apply: rebuild the store calldata with (blob', r'), keeping id and digest.
	redactedCalldata, err := redactabledeposit.RedactedStoreCalldata(origCalldata, blobPrime, rPrime)
	require.NoError(err)

	// The redacted opening keeps id + digest and carries (blob'="", r').
	// Strip the 4-byte selector that Pack prepends before unpacking the args.
	gotID, gotBlob, gotR, gotDigest, err := redactabledeposit.UnpackStoreInput(redactedCalldata[4:])
	require.NoError(err)
	require.Equal(id, gotID)
	require.Empty(gotBlob, "blob must be removed off-state")
	require.Equal(rPrime, gotR)
	require.Equal(digest, gotDigest, "the committed digest must be unchanged")

	// The collision holds: the digest still commits to the new content.
	require.True(chameleon.Verify(hk, blobPrime, rPrime, digest), "CH(blob', r') must equal D")
	require.False(bytes.Contains(redactedCalldata, blob), "the original blob is gone from calldata")

	// Block-level apply: swap the tx body via RedactBlock and confirm the
	// committed roots are frozen and only the tx changes (no re-execution).
	to := common.Address{0x0d}
	key, err := crypto.GenerateKey()
	require.NoError(err)
	signer := types.LatestSignerForChainID(big.NewInt(1337))
	mkTx := func(data []byte) *types.Transaction {
		tx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{
			ChainID:   big.NewInt(1337),
			Nonce:     0,
			GasFeeCap: big.NewInt(1),
			Gas:       2_000_000,
			To:        &to,
			Data:      data,
		}), signer, key)
		require.NoError(err)
		return tx
	}

	origTx := mkTx(origCalldata)
	stateRoot := common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111")
	receiptRoot := common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222")
	header := &types.Header{
		Number:      big.NewInt(1),
		Root:        stateRoot,
		ReceiptHash: receiptRoot,
		TxHash:      types.DeriveSha(types.Transactions{origTx}, trie.NewStackTrie(nil)),
	}
	original := types.NewBlockWithHeader(header).WithBody(types.Body{Transactions: []*types.Transaction{origTx}})

	redacted := redact.RedactBlock(original, []*types.Transaction{mkTx(redactedCalldata)})

	require.Equal(original.Root(), redacted.Root(), "state root must be frozen")
	require.Equal(original.ReceiptHash(), redacted.ReceiptHash(), "receipt root must be frozen")
	require.NotEqual(original.TxHash(), redacted.TxHash(), "tx root changes with the new body")
	require.False(bytes.Contains(redacted.Transactions()[0].Data(), blob), "redacted block carries no blob")
}

// TestFindAndRebuildStoreTx: find the store tx for an id in a block, then rebuild
// it with a new opening (no sender key needed).
func TestFindAndRebuildStoreTx(t *testing.T) {
	require := require.New(t)

	hk, tk, err := chameleon.KeyGen()
	require.NoError(err)
	blob := bytes.Repeat([]byte{0x11}, 64)
	r := bytes.Repeat([]byte{0x22}, 32)
	digest := chameleon.Hash(hk, blob, r)
	id := crypto.Keccak256Hash([]byte("dep"))
	to := common.Address{0x0d}
	other := common.Address{0x99}

	calldata, err := redactabledeposit.PackStore(id, blob, r, digest)
	require.NoError(err)

	key, err := crypto.GenerateKey()
	require.NoError(err)
	signer := types.LatestSignerForChainID(big.NewInt(1337))
	mk := func(nonce uint64, dst common.Address, data []byte) *types.Transaction {
		tx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{
			ChainID: big.NewInt(1337), Nonce: nonce, GasFeeCap: big.NewInt(1), Gas: 2_000_000, To: &dst, Data: data,
		}), signer, key)
		require.NoError(err)
		return tx
	}
	unrelated := mk(0, other, nil)
	storeTx := mk(1, to, calldata)
	txs := []*types.Transaction{unrelated, storeTx}
	block := types.NewBlockWithHeader(&types.Header{
		Number: big.NewInt(1),
		TxHash: types.DeriveSha(types.Transactions(txs), trie.NewStackTrie(nil)),
	}).WithBody(types.Body{Transactions: txs})

	found, ok := redactabledeposit.FindStoreTx(block, to, id)
	require.True(ok)
	require.Equal(storeTx.Hash(), found.Hash())
	_, ok = redactabledeposit.FindStoreTx(block, to, crypto.Keccak256Hash([]byte("nope")))
	require.False(ok)

	rPrime, err := chameleon.Forge(tk, blob, r, []byte{})
	require.NoError(err)
	redactedTx, err := redactabledeposit.RebuildRedactedStoreTx(found, []byte{}, rPrime)
	require.NoError(err)
	require.NotEqual(found.Hash(), redactedTx.Hash())
	require.Equal(found.Nonce(), redactedTx.Nonce())
	require.Equal(found.Gas(), redactedTx.Gas())

	gotID, gotBlob, gotR, gotDigest, err := redactabledeposit.UnpackStoreInput(redactedTx.Data()[4:])
	require.NoError(err)
	require.Equal(id, gotID)
	require.Empty(gotBlob)
	require.Equal(rPrime, gotR)
	require.Equal(digest, gotDigest)
	require.True(chameleon.Verify(hk, []byte{}, rPrime, digest))
}
