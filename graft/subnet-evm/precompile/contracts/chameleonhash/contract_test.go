// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chameleonhash

import (
	"bytes"
	"testing"

	"github.com/ava-labs/libevm/common"
	"github.com/stretchr/testify/require"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact/chameleon"
)

// The precompile reproduces chameleon.Hash exactly.
func TestChameleonHashPrecompileMatchesPrimitive(t *testing.T) {
	require := require.New(t)

	hk, _, err := chameleon.KeyGen()
	require.NoError(err)
	m := []byte("the message")
	r := bytes.Repeat([]byte{0x07}, 32)
	want := chameleon.Hash(hk, m, r)

	input, err := PackHash(hk.Bytes(), m, r)
	require.NoError(err)

	// hashFn ignores accessibleState, so nil is fine here.
	ret, _, err := ChameleonHashPrecompile.Run(nil, common.Address{}, ContractAddress, input, hashGasCost, false)
	require.NoError(err)

	got, err := UnpackHashOutput(ret)
	require.NoError(err)
	require.Equal(want, got)
}

// A malformed public key is rejected.
func TestChameleonHashPrecompileBadKey(t *testing.T) {
	input, err := PackHash([]byte{0x01, 0x02}, []byte("m"), bytes.Repeat([]byte{0x07}, 32))
	require.NoError(t, err)

	_, _, err = ChameleonHashPrecompile.Run(nil, common.Address{}, ContractAddress, input, hashGasCost, false)
	require.Error(t, err)
}
