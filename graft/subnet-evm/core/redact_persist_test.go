// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package core

import (
	"bytes"
	"context"
	"math/big"
	"testing"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core/rawdb"
	"github.com/ava-labs/libevm/core/types"
	"github.com/ava-labs/libevm/crypto"
	"github.com/stretchr/testify/require"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/consensus/dummy"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/params"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/plugin/evm/customtypes"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact"

	ethparams "github.com/ava-labs/libevm/params"
)

func TestRedactZeroesEOAInputAndPersists(t *testing.T) {
	var (
		key, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr   = crypto.PubkeyToAddress(key.PublicKey)
		config = params.TestChainConfig
		signer = types.LatestSigner(config)
		eoa    = common.Address{0x99}
		gspec  = &Genesis{
			Config:   config,
			Alloc:    types.GenesisAlloc{addr: {Balance: big.NewInt(1_000_000_000_000_000_000)}},
			GasLimit: params.GetExtra(config).FeeConfig.GasLimit.Uint64(),
		}
		bigInput = bytes.Repeat([]byte{0xab}, 1024)
	)

	db, chain, _, err := GenerateChainWithGenesis(gspec, dummy.NewCoinbaseFaker(), 2, 10, func(i int, gen *BlockGen) {
		if i == 0 {
			tx, txErr := types.SignTx(types.NewTx(&types.DynamicFeeTx{
				Nonce:     0,
				GasTipCap: big.NewInt(0),
				GasFeeCap: big.NewInt(225_000_000_000),
				Gas:       ethparams.TxGas + 16*uint64(len(bigInput)),
				To:        &eoa,
				Value:     big.NewInt(0),
				Data:      bigInput,
			}), signer, key)
			require.NoError(t, txErr)
			gen.AddTx(tx)
		}
	})
	require.NoError(t, err)
	block0, block1 := chain[0], chain[1]

	// Put the generated chain on disk (genesis is already committed).
	for _, b := range chain {
		rawdb.WriteBlock(db, b)
		rawdb.WriteCanonicalHash(db, b.Hash(), b.NumberU64())
	}

	// Sanity: the block really holds the large input before redaction.
	require.Len(t, block0.Transactions(), 1)
	require.Equal(t, bigInput, block0.Transactions()[0].Data())

	// Redact: same tx but with the input zeroed.
	redactedTx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{
		Nonce:     0,
		GasTipCap: big.NewInt(0),
		GasFeeCap: big.NewInt(225_000_000_000),
		Gas:       block0.Transactions()[0].Gas(),
		To:        &eoa,
		Value:     big.NewInt(0),
		Data:      nil,
	}), signer, key)
	require.NoError(t, err)

	redacted := redact.RedactBlock(block0, []*types.Transaction{redactedTx})
	require.NoError(t, redact.Persist(db, block0.Hash(), redacted))

	// Read the block back from disk under its original hash.
	got := rawdb.ReadBlock(db, block0.Hash(), block0.NumberU64())
	require.NotNil(t, got)

	// Body was replaced and the input is gone.
	require.Len(t, got.Transactions(), 1)
	require.Empty(t, got.Transactions()[0].Data())

	// These fields stay as they were before the redaction.
	require.Equal(t, block0.Root(), got.Root())
	require.Equal(t, block0.ReceiptHash(), got.ReceiptHash())

	// TxHash follows the new body and InitialTxHash keeps the original hash.
	require.Equal(t, redactedTx.Hash(), got.Transactions()[0].Hash())
	require.NotEqual(t, block0.TxHash(), got.TxHash())
	require.Equal(t, block0.TxHash(), *customtypes.GetHeaderExtra(got.Header()).InitialTxHash)

	// The new link is broken and the old link still matches the child.
	require.NotEqual(t, block1.ParentHash(), redact.NewLink(got.Header()))
	require.True(t, redact.ValidParentLink(context.Background(), block1.ParentHash(), got.Header()))

	// The state root is untouched.
	gotChild := rawdb.ReadBlock(db, block1.Hash(), block1.NumberU64())
	require.NotNil(t, gotChild)
	require.Equal(t, block1.Root(), gotChild.Root())
}
