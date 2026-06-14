// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package core

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core/rawdb"
	"github.com/ava-labs/libevm/core/types"
	"github.com/ava-labs/libevm/crypto"
	"github.com/ava-labs/libevm/ethdb"
	"github.com/stretchr/testify/require"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/params"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact"

	ethparams "github.com/ava-labs/libevm/params"
)

// ValidateCanonicalChain must still pass when a middle block has been
// redacted. The redacted block is reachable through its old link and its
// stored receipts/tx-index are no longer matched against the new body.
func TestValidateCanonicalChainWithRedactedBlock(t *testing.T) {
	var (
		key, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr   = crypto.PubkeyToAddress(key.PublicKey)
		config = params.TestChainConfig
		signer = types.LatestSigner(config)
		db     = rawdb.NewMemoryDatabase()
		to     = common.Address{0x99}
		gspec  = &Genesis{
			Config:   config,
			Alloc:    types.GenesisAlloc{addr: {Balance: big.NewInt(1_000_000_000_000_000_000)}},
			GasLimit: params.GetExtra(config).FeeConfig.GasLimit.Uint64(),
		}
	)

	bc, err := createBlockChain(db, DefaultCacheConfig, gspec, common.Hash{})
	require.NoError(t, err)

	_, chain, _, err := GenerateChainWithGenesis(gspec, bc.engine, 3, 10, func(i int, gen *BlockGen) {
		tx, txErr := types.SignTx(types.NewTx(&types.DynamicFeeTx{
			Nonce:     uint64(i),
			GasTipCap: big.NewInt(0),
			GasFeeCap: big.NewInt(225_000_000_000),
			Gas:       ethparams.TxGas,
			To:        &to,
			Value:     big.NewInt(1),
		}), signer, key)
		require.NoError(t, txErr)
		gen.AddTx(tx)
	})
	require.NoError(t, err)

	_, err = bc.InsertChain(chain)
	require.NoError(t, err)
	for _, blk := range chain {
		require.NoError(t, bc.Accept(blk))
	}
	bc.DrainAcceptorQueue()

	head := chain[2]
	block1 := chain[1]

	// Redact the middle block: empty body, recompute TxHash, freeze the rest.
	redacted := redact.RedactBlock(block1, nil)
	require.NoError(t, redact.Persist(db, block1.Hash(), redacted))

	bc.Stop()

	// Reopen with cold caches so reads come from disk (the redacted block).
	bc2, err := createBlockChain(db, DefaultCacheConfig, gspec, head.Hash())
	require.NoError(t, err)
	defer bc2.Stop()

	require.NoError(t, bc2.ValidateCanonicalChain())
}

// The re-execution insert path must refuse a redacted block with a clear error
// instead of failing later with a misleading state-root mismatch.
func TestInsertBlockRejectsRedacted(t *testing.T) {
	var (
		key, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr   = crypto.PubkeyToAddress(key.PublicKey)
		config = params.TestChainConfig
		signer = types.LatestSigner(config)
		db     = rawdb.NewMemoryDatabase()
		to     = common.Address{0x99}
		gspec  = &Genesis{
			Config:   config,
			Alloc:    types.GenesisAlloc{addr: {Balance: big.NewInt(1_000_000_000_000_000_000)}},
			GasLimit: params.GetExtra(config).FeeConfig.GasLimit.Uint64(),
		}
	)

	bc, err := createBlockChain(db, DefaultCacheConfig, gspec, common.Hash{})
	require.NoError(t, err)
	defer bc.Stop()

	_, chain, _, err := GenerateChainWithGenesis(gspec, bc.engine, 1, 10, func(_ int, gen *BlockGen) {
		tx, txErr := types.SignTx(types.NewTx(&types.DynamicFeeTx{
			Nonce:     0,
			GasTipCap: big.NewInt(0),
			GasFeeCap: big.NewInt(225_000_000_000),
			Gas:       ethparams.TxGas,
			To:        &to,
			Value:     big.NewInt(1),
		}), signer, key)
		require.NoError(t, txErr)
		gen.AddTx(tx)
	})
	require.NoError(t, err)

	redacted := redact.RedactBlock(chain[0], nil)
	err = bc.InsertBlock(redacted)
	require.ErrorIs(t, err, errCannotReexecuteRedactedBlock)
}

// A block where only ONE of two transactions is redacted: the surviving tx must
// still be checked (its receipt/tx-index attribution), only the redacted one is
// tolerated.
func TestValidateCanonicalChainRedactedKeepsSurvivingTx(t *testing.T) {
	var (
		key, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr   = crypto.PubkeyToAddress(key.PublicKey)
		config = params.TestChainConfig
		signer = types.LatestSigner(config)
		db     = rawdb.NewMemoryDatabase()
		to     = common.Address{0x99}
		gspec  = &Genesis{
			Config:   config,
			Alloc:    types.GenesisAlloc{addr: {Balance: big.NewInt(1_000_000_000_000_000_000)}},
			GasLimit: params.GetExtra(config).FeeConfig.GasLimit.Uint64(),
		}
	)

	mkTx := func(nonce uint64, data []byte) *types.Transaction {
		tx, txErr := types.SignTx(types.NewTx(&types.DynamicFeeTx{
			Nonce:     nonce,
			GasTipCap: big.NewInt(0),
			GasFeeCap: big.NewInt(225_000_000_000),
			Gas:       ethparams.TxGas + 16*uint64(len(data)),
			To:        &to,
			Value:     big.NewInt(1),
			Data:      data,
		}), signer, key)
		require.NoError(t, txErr)
		return tx
	}

	bc, err := createBlockChain(db, DefaultCacheConfig, gspec, common.Hash{})
	require.NoError(t, err)

	// Block 0 carries two txs (the first has an input we will redact); block 1 is head.
	_, chain, _, err := GenerateChainWithGenesis(gspec, bc.engine, 2, 10, func(i int, gen *BlockGen) {
		if i == 0 {
			gen.AddTx(mkTx(0, []byte{0xaa, 0xbb, 0xcc, 0xdd}))
			gen.AddTx(mkTx(1, nil))
		} else {
			gen.AddTx(mkTx(2, nil))
		}
	})
	require.NoError(t, err)

	_, err = bc.InsertChain(chain)
	require.NoError(t, err)
	for _, blk := range chain {
		require.NoError(t, bc.Accept(blk))
	}
	bc.DrainAcceptorQueue()

	head := chain[1]
	target := chain[0]
	survivingTx := target.Transactions()[1]

	// Redact only the first tx (zero its input); keep the second tx intact.
	redactedTx := mkTx(0, nil)
	redacted := redact.RedactBlock(target, []*types.Transaction{redactedTx, survivingTx})
	require.NoError(t, redact.Persist(db, target.Hash(), redacted))

	bc.Stop()

	bc2, err := createBlockChain(db, DefaultCacheConfig, gspec, head.Hash())
	require.NoError(t, err)
	defer bc2.Stop()

	require.NoError(t, bc2.ValidateCanonicalChain())
}

// setupRedactedFirstTxChain builds and accepts a 2-block chain whose first
// block carries two txs, then redacts only the first tx (keeping the second)
// and persists the redacted block. It returns the db, genesis, the head and the
// (original) redacted block, leaving it to the caller to store a proof and
// reopen the chain.
func setupRedactedFirstTxChain(t *testing.T) (ethdb.Database, *Genesis, *types.Block, *types.Block) {
	t.Helper()
	var (
		key, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr   = crypto.PubkeyToAddress(key.PublicKey)
		config = params.TestChainConfig
		signer = types.LatestSigner(config)
		db     = rawdb.NewMemoryDatabase()
		to     = common.Address{0x99}
		gspec  = &Genesis{
			Config:   config,
			Alloc:    types.GenesisAlloc{addr: {Balance: big.NewInt(1_000_000_000_000_000_000)}},
			GasLimit: params.GetExtra(config).FeeConfig.GasLimit.Uint64(),
		}
	)
	mkTx := func(nonce uint64, data []byte) *types.Transaction {
		tx, txErr := types.SignTx(types.NewTx(&types.DynamicFeeTx{
			Nonce:     nonce,
			GasTipCap: big.NewInt(0),
			GasFeeCap: big.NewInt(225_000_000_000),
			Gas:       ethparams.TxGas + 16*uint64(len(data)),
			To:        &to,
			Value:     big.NewInt(1),
			Data:      data,
		}), signer, key)
		require.NoError(t, txErr)
		return tx
	}

	bc, err := createBlockChain(db, DefaultCacheConfig, gspec, common.Hash{})
	require.NoError(t, err)

	_, chain, _, err := GenerateChainWithGenesis(gspec, bc.engine, 2, 10, func(i int, gen *BlockGen) {
		if i == 0 {
			gen.AddTx(mkTx(0, []byte{0xaa, 0xbb, 0xcc, 0xdd}))
			gen.AddTx(mkTx(1, nil))
		} else {
			gen.AddTx(mkTx(2, nil))
		}
	})
	require.NoError(t, err)

	_, err = bc.InsertChain(chain)
	require.NoError(t, err)
	for _, blk := range chain {
		require.NoError(t, bc.Accept(blk))
	}
	bc.DrainAcceptorQueue()

	target := chain[0]
	redacted := redact.RedactBlock(target, []*types.Transaction{mkTx(0, nil), target.Transactions()[1]})
	require.NoError(t, redact.Persist(db, target.Hash(), redacted))
	bc.Stop()

	return db, gspec, chain[1], target
}

// buildValidationChain builds and accepts an n-block chain, redacts the given
// percentage of its (non-head) blocks (storing a proof for each), reopens the
// chain with cold caches and returns it ready for ValidateCanonicalChain.
func buildValidationChain(b *testing.B, n, redactedPercent int) *BlockChain {
	b.Helper()
	var (
		key, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr   = crypto.PubkeyToAddress(key.PublicKey)
		config = params.TestChainConfig
		signer = types.LatestSigner(config)
		db     = rawdb.NewMemoryDatabase()
		to     = common.Address{0x99}
		gspec  = &Genesis{
			Config:   config,
			Alloc:    types.GenesisAlloc{addr: {Balance: big.NewInt(1_000_000_000_000_000_000)}},
			GasLimit: params.GetExtra(config).FeeConfig.GasLimit.Uint64(),
		}
	)

	bc, err := createBlockChain(db, DefaultCacheConfig, gspec, common.Hash{})
	if err != nil {
		b.Fatal(err)
	}
	_, chain, _, err := GenerateChainWithGenesis(gspec, bc.engine, n, 10, func(i int, gen *BlockGen) {
		tx, txErr := types.SignTx(types.NewTx(&types.DynamicFeeTx{
			Nonce:     uint64(i),
			GasTipCap: big.NewInt(0),
			GasFeeCap: big.NewInt(225_000_000_000),
			Gas:       ethparams.TxGas,
			To:        &to,
			Value:     big.NewInt(1),
		}), signer, key)
		if txErr != nil {
			b.Fatal(txErr)
		}
		gen.AddTx(tx)
	})
	if err != nil {
		b.Fatal(err)
	}
	if _, err := bc.InsertChain(chain); err != nil {
		b.Fatal(err)
	}
	for _, blk := range chain {
		if err := bc.Accept(blk); err != nil {
			b.Fatal(err)
		}
	}
	bc.DrainAcceptorQueue()

	head := chain[len(chain)-1]
	redactCount := (len(chain) - 1) * redactedPercent / 100
	for j := 0; j < redactCount; j++ {
		blk := chain[j]
		redacted := redact.RedactBlock(blk, nil)
		if err := redact.Persist(db, blk.Hash(), redacted); err != nil {
			b.Fatal(err)
		}
		proof := &redact.Proof{Proposal: redact.Proposal{OriginalHash: blk.Hash()}}
		raw, err := proof.Bytes()
		if err != nil {
			b.Fatal(err)
		}
		if err := redact.WriteRedactionProof(db, blk.Hash(), raw); err != nil {
			b.Fatal(err)
		}
	}
	bc.Stop()

	bc2, err := createBlockChain(db, DefaultCacheConfig, gspec, head.Hash())
	if err != nil {
		b.Fatal(err)
	}
	return bc2
}

// BenchmarkValidateCanonicalChainRedacted measures full-chain validation time as
// the fraction of redacted blocks grows.
func BenchmarkValidateCanonicalChainRedacted(b *testing.B) {
	const chainLen = 32
	for _, frac := range []int{0, 25, 50, 100} {
		b.Run(fmt.Sprintf("redacted_%d%%", frac), func(b *testing.B) {
			bc := buildValidationChain(b, chainLen, frac)
			defer bc.Stop()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := bc.ValidateCanonicalChain(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func writeProofIndices(t *testing.T, db ethdb.Database, blockHash common.Hash, indices []uint64) {
	t.Helper()
	proof := &redact.Proof{Proposal: redact.Proposal{OriginalHash: blockHash, RedactedIndices: indices}}
	raw, err := proof.Bytes()
	require.NoError(t, err)
	require.NoError(t, redact.WriteRedactionProof(db, blockHash, raw))
}

// With a proof authorizing the redacted index, validation accepts the block and
// still checks the surviving transaction.
func TestValidateCanonicalChainRedactedPrecisionAccepts(t *testing.T) {
	db, gspec, head, target := setupRedactedFirstTxChain(t)
	writeProofIndices(t, db, target.Hash(), []uint64{0})

	bc, err := createBlockChain(db, DefaultCacheConfig, gspec, head.Hash())
	require.NoError(t, err)
	defer bc.Stop()

	require.NoError(t, bc.ValidateCanonicalChain())
}

// If the proof does NOT authorize the change at index 0, validation must catch
// it (the change is treated as a corruption, not an authorized redaction).
func TestValidateCanonicalChainRedactedPrecisionRejectsUnauthorized(t *testing.T) {
	db, gspec, head, target := setupRedactedFirstTxChain(t)
	writeProofIndices(t, db, target.Hash(), nil) // claims nothing was redacted

	bc, err := createBlockChain(db, DefaultCacheConfig, gspec, head.Hash())
	require.NoError(t, err)
	defer bc.Stop()

	require.Error(t, bc.ValidateCanonicalChain())
}
