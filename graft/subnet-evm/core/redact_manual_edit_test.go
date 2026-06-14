// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package core

import (
	"context"
	"math/big"
	"testing"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core/types"
	"github.com/ava-labs/libevm/crypto"
	"github.com/ava-labs/libevm/trie"
	"github.com/stretchr/testify/require"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/consensus/dummy"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/params"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/plugin/evm/customtypes"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact"

	ethparams "github.com/ava-labs/libevm/params"
)

// Build a small chain, redact one block's body and check 
// that the link to its child still validates through the old link.
func TestManualEditValidatesViaOldLink(t *testing.T) {
	var (
		key, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr   = crypto.PubkeyToAddress(key.PublicKey)
		config = params.TestChainConfig
		signer = types.LatestSigner(config)
		gspec  = &Genesis{
			Config:   config,
			Alloc:    types.GenesisAlloc{addr: {Balance: big.NewInt(1_000_000_000_000_000_000)}},
			GasLimit: params.GetExtra(config).FeeConfig.GasLimit.Uint64(),
		}
	)

	to := common.Address{0x99}
	_, chain, _, err := GenerateChainWithGenesis(gspec, dummy.NewCoinbaseFaker(), 2, 10, func(i int, gen *BlockGen) {
		if i == 0 {
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
		}
	})
	require.NoError(t, err)

	parent, child := chain[0], chain[1]

	// Before redaction: InitialTxHash == TxHash and the child links to both.
	parentExtra := customtypes.GetHeaderExtra(parent.Header())
	require.NotNil(t, parentExtra.InitialTxHash)
	require.Equal(t, parent.TxHash(), *parentExtra.InitialTxHash)
	require.Equal(t, child.ParentHash(), redact.NewLink(parent.Header()))
	require.Equal(t, child.ParentHash(), redact.OldLink(parent.Header()))

	// Redact: empty the body, recompute TxHash, freeze everything else.
	redacted := types.CopyHeader(parent.Header())
	redacted.TxHash = types.DeriveSha(types.Transactions{}, trie.NewStackTrie(nil))

	// These fields are left untouched.
	require.Equal(t, parent.Root(), redacted.Root)
	require.Equal(t, parent.ReceiptHash(), redacted.ReceiptHash)
	require.Equal(t, parent.TxHash(), *customtypes.GetHeaderExtra(redacted).InitialTxHash)

	// The new link is now broken, but the old link still matches the child.
	require.NotEqual(t, child.ParentHash(), redact.NewLink(redacted))
	require.Equal(t, child.ParentHash(), redact.OldLink(redacted))

	// And the dual-link validation accepts the redacted parent.
	require.True(t, redact.ValidParentLink(context.Background(), child.ParentHash(), redacted))
}
