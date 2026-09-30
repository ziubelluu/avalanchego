// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package core

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core/rawdb"
	"github.com/ava-labs/libevm/core/types"
	"github.com/ava-labs/libevm/crypto"
	"github.com/stretchr/testify/require"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/params"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact"

	ethparams "github.com/ava-labs/libevm/params"
)

// TestValidateRejectsRedactedBlockByDefault: a chain that nobody gave a policy
// to must not accept a redacted block. Nothing approved the redaction, so the
// link to the redacted block is not valid.
func TestValidateRejectsRedactedBlockByDefault(t *testing.T) {
	var (
		key, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr   = crypto.PubkeyToAddress(key.PublicKey)
		config = params.TestChainConfig
		signer = types.LatestSigner(config)
		db     = rawdb.NewMemoryDatabase()
		eoa    = common.Address{0x99}
		gspec  = &Genesis{
			Config:   config,
			Alloc:    types.GenesisAlloc{addr: {Balance: big.NewInt(1_000_000_000_000_000_000)}},
			GasLimit: params.GetExtra(config).FeeConfig.GasLimit.Uint64(),
		}
		blob = bytes.Repeat([]byte{0xDE, 0xAD, 0xBE, 0xEF}, 256)
	)

	mkTx := func(nonce uint64, data []byte) *types.Transaction {
		tx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{
			Nonce:     nonce,
			GasTipCap: big.NewInt(0),
			GasFeeCap: big.NewInt(225_000_000_000),
			Gas:       ethparams.TxGas + 16*uint64(len(data)),
			To:        &eoa,
			Value:     big.NewInt(0),
			Data:      data,
		}), signer, key)
		require.NoError(t, err)
		return tx
	}

	bc, err := createBlockChain(db, DefaultCacheConfig, gspec, common.Hash{})
	require.NoError(t, err)

	_, chain, _, err := GenerateChainWithGenesis(gspec, bc.engine, 2, 10, func(i int, gen *BlockGen) {
		if i == 0 {
			gen.AddTx(mkTx(0, blob))
		} else {
			gen.AddTx(mkTx(1, nil))
		}
	})
	require.NoError(t, err)
	_, err = bc.InsertChain(chain)
	require.NoError(t, err)
	for _, blk := range chain {
		require.NoError(t, bc.Accept(blk))
	}
	bc.DrainAcceptorQueue()

	// Before the redaction the chain is fine.
	require.NoError(t, bc.ValidateCanonicalChain())

	// Redact block 1. There is a proof in the database, but this chain has no
	// policy that could check it.
	target := chain[0]
	newTxs := []*types.Transaction{mkTx(0, nil)}
	proof := &redact.Proof{Proposal: redact.Proposal{
		OriginalHash:    target.Hash(),
		NewTxHash:       redact.RedactBlock(target, newTxs).TxHash(),
		RedactedIndices: []uint64{0},
	}}
	proofBytes, err := proof.Bytes()
	require.NoError(t, err)
	_, err = bc.RedactStored(target, newTxs, proofBytes)
	require.NoError(t, err)
	bc.Stop()

	// Open the chain again without setting any policy.
	bc2, err := createBlockChain(db, DefaultCacheConfig, gspec, chain[1].Hash())
	require.NoError(t, err)
	defer bc2.Stop()

	err = bc2.ValidateCanonicalChain()
	require.Error(t, err, "a redacted block must not be accepted without a policy")
	require.ErrorContains(t, err, "parent block")

	// The only thing missing was the approval: allow everything and the same
	// chain validates.
	bc2.SetRedactionPolicy(redact.AllowAllForTesting)
	require.NoError(t, bc2.ValidateCanonicalChain())
}
