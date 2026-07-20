// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"math/big"
	"testing"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core/types"
	"github.com/ava-labs/libevm/crypto"
	"github.com/stretchr/testify/require"
)

func TestRebuildTxWithData(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	to := common.Address{0x11}
	signer := types.LatestSignerForChainID(big.NewInt(1))

	orig, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{
		ChainID: big.NewInt(1), Nonce: 5, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2),
		Gas: 100000, To: &to, Value: big.NewInt(7), Data: []byte("secret data"),
	}), signer, key)
	require.NoError(t, err)

	rebuilt, err := RebuildTxWithData(orig, nil)
	require.NoError(t, err)

	require.Empty(t, rebuilt.Data(), "data must be cleared")
	require.Equal(t, orig.Nonce(), rebuilt.Nonce())
	require.Equal(t, orig.Gas(), rebuilt.Gas())
	require.Equal(t, orig.Value(), rebuilt.Value())
	require.NotEqual(t, orig.Hash(), rebuilt.Hash(), "hash changes with the data")

	ov, or, os := orig.RawSignatureValues()
	rv, rr, rs := rebuilt.RawSignatureValues()
	require.Equal(t, ov, rv)
	require.Equal(t, or, rr)
	require.Equal(t, os, rs)
}

func TestRebuildTxWithDataRejectsNonDynamicFee(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	to := common.Address{0x11}

	legacy, err := types.SignTx(types.NewTx(&types.LegacyTx{
		Nonce: 0, GasPrice: big.NewInt(1), Gas: 21000, To: &to,
	}), types.HomesteadSigner{}, key)
	require.NoError(t, err)

	_, err = RebuildTxWithData(legacy, nil)
	require.Error(t, err, "non dynamic-fee tx must be rejected")
}
