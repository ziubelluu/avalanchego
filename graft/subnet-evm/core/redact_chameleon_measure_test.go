// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package core

import (
	"bytes"
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core/rawdb"
	"github.com/ava-labs/libevm/core/types"
	"github.com/ava-labs/libevm/crypto"
	"github.com/ava-labs/libevm/trie"
	"github.com/stretchr/testify/require"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact/redactabledeposit"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact/chameleon"
)

// buildStoreBlock builds a single-tx block whose tx calls store(id, blob, r, D),
// returning the block, the original tx, and the signing material.
func buildStoreBlock(tb testing.TB, blob, r, digest []byte) (*types.Block, *types.Transaction, *ecdsa.PrivateKey, types.Signer) {
	tb.Helper()
	key, err := crypto.GenerateKey()
	require.NoError(tb, err)
	signer := types.LatestSignerForChainID(big.NewInt(1337))
	to := common.Address{0x0d}
	id := crypto.Keccak256Hash([]byte("deposit-1"))

	calldata, err := redactabledeposit.PackStore(id, blob, r, digest)
	require.NoError(tb, err)
	tx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{
		ChainID: big.NewInt(1337), Nonce: 0, GasFeeCap: big.NewInt(1), Gas: 3_000_000, To: &to, Data: calldata,
	}), signer, key)
	require.NoError(tb, err)

	header := &types.Header{
		Number:      big.NewInt(1),
		Root:        common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"),
		ReceiptHash: common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222"),
		TxHash:      types.DeriveSha(types.Transactions{tx}, trie.NewStackTrie(nil)),
	}
	block := types.NewBlockWithHeader(header).WithBody(types.Body{Transactions: []*types.Transaction{tx}})
	return block, tx, key, signer
}

// TestMeasureRootStableAcrossRedactions: however many times we redact a deposit,
// and whatever we redact it to, the roots don't move. Only the digest D lives on
// state, and it never changes.
func TestMeasureRootStableAcrossRedactions(t *testing.T) {
	require := require.New(t)

	hk, tk, err := chameleon.KeyGen()
	require.NoError(err)
	blob := bytes.Repeat([]byte{0xAB, 0xCD, 0xEF, 0x12}, 256)
	r := bytes.Repeat([]byte{0x07}, 32)
	digest := chameleon.Hash(hk, blob, r)

	block0, origTx, key, signer := buildStoreBlock(t, blob, r, digest)
	to := common.Address{0x0d}

	replacements := [][]byte{
		{},
		[]byte("a short note"),
		bytes.Repeat([]byte{0x55}, 4096),
	}
	for k, blobPrime := range replacements {
		rPrime, err := chameleon.Forge(tk, blob, r, blobPrime)
		require.NoError(err)
		require.True(chameleon.Verify(hk, blobPrime, rPrime, digest), "redaction %d: collision must hold", k)

		newCalldata, err := redactabledeposit.RedactedStoreCalldata(origTx.Data(), blobPrime, rPrime)
		require.NoError(err)
		newTx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{
			ChainID: big.NewInt(1337), Nonce: 0, GasFeeCap: big.NewInt(1), Gas: origTx.Gas(), To: &to, Data: newCalldata,
		}), signer, key)
		require.NoError(err)

		redacted := redact.RedactBlock(block0, []*types.Transaction{newTx})
		require.Equal(block0.Root(), redacted.Root(), "redaction %d: state root must be frozen", k)
		require.Equal(block0.ReceiptHash(), redacted.ReceiptHash(), "redaction %d: receipt root must be frozen", k)
	}

	t.Logf("digest committed in state: %d bytes (constant); redacted %d times, state root never changed",
		len(digest), len(replacements))
}

// BenchmarkTxChannelRedactionApply is the baseline: redact a block by swapping
// its body and saving it, no chameleon work.
func BenchmarkTxChannelRedactionApply(b *testing.B) {
	hk, _, err := chameleon.KeyGen()
	require.NoError(b, err)
	blob := bytes.Repeat([]byte{0xAB, 0xCD, 0xEF, 0x12}, 256)
	r := bytes.Repeat([]byte{0x07}, 32)
	digest := chameleon.Hash(hk, blob, r)

	block0, origTx, key, signer := buildStoreBlock(b, blob, r, digest)
	to := common.Address{0x0d}
	emptyTx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{
		ChainID: big.NewInt(1337), Nonce: 0, GasFeeCap: big.NewInt(1), Gas: origTx.Gas(), To: &to,
	}), signer, key)
	require.NoError(b, err)
	db := rawdb.NewMemoryDatabase()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		redacted := redact.RedactBlock(block0, []*types.Transaction{emptyTx})
		if err := redact.Persist(db, block0.Hash(), redacted); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkStateRedactionApply measures the full state-data redaction:
// forge + calldata rebuild + body swap + save. The gap with the baseline above
// is the extra cost of the chameleon scheme.
func BenchmarkStateRedactionApply(b *testing.B) {
	hk, tk, err := chameleon.KeyGen()
	require.NoError(b, err)
	_ = hk
	blob := bytes.Repeat([]byte{0xAB, 0xCD, 0xEF, 0x12}, 256)
	r := bytes.Repeat([]byte{0x07}, 32)
	digest := chameleon.Hash(hk, blob, r)

	block0, origTx, key, signer := buildStoreBlock(b, blob, r, digest)
	to := common.Address{0x0d}
	blobPrime := []byte{}
	db := rawdb.NewMemoryDatabase()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rPrime, err := chameleon.Forge(tk, blob, r, blobPrime)
		if err != nil {
			b.Fatal(err)
		}
		newCalldata, err := redactabledeposit.RedactedStoreCalldata(origTx.Data(), blobPrime, rPrime)
		if err != nil {
			b.Fatal(err)
		}
		newTx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{
			ChainID: big.NewInt(1337), Nonce: 0, GasFeeCap: big.NewInt(1), Gas: origTx.Gas(), To: &to, Data: newCalldata,
		}), signer, key)
		if err != nil {
			b.Fatal(err)
		}
		redacted := redact.RedactBlock(block0, []*types.Transaction{newTx})
		if err := redact.Persist(db, block0.Hash(), redacted); err != nil {
			b.Fatal(err)
		}
	}
}
