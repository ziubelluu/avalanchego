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

func runVerify(t *testing.T, hk, m, r, digest []byte) (bool, error) {
	t.Helper()
	input, err := PackVerify(hk, m, r, digest)
	require.NoError(t, err)
	// verifyFn ignores accessibleState, so nil is fine here.
	ret, _, err := ChameleonHashPrecompile.Run(nil, common.Address{}, ContractAddress, input, verifyGasCost, false)
	if err != nil {
		return false, err
	}
	return UnpackVerifyOutput(ret)
}

// The precompile answers like chameleon.Verify.
func TestVerifyPrecompileAgreesWithPrimitive(t *testing.T) {
	require := require.New(t)
	hk, tk, err := chameleon.KeyGen()
	require.NoError(err)
	m := []byte("the message")
	digest, r, err := chameleon.Hash(hk, m)
	require.NoError(err)

	ok, err := runVerify(t, hk.Bytes(), m, r, digest)
	require.NoError(err)
	require.True(ok)

	// a forged opening is good too
	rPrime, err := chameleon.Forge(tk, m, r, []byte{}, digest)
	require.NoError(err)
	ok, err = runVerify(t, hk.Bytes(), []byte{}, rPrime, digest)
	require.NoError(err)
	require.True(ok)

	// wrong message, wrong digest, wrong randomness: false, not an error
	for name, args := range map[string][][]byte{
		"message":    {m[:3], r, digest},
		"digest":     {m, r, bytes.Repeat([]byte{0x01}, chameleon.DigestLen)},
		"randomness": {m, bytes.Repeat([]byte{0x01}, chameleon.RandomnessLen), digest},
	} {
		ok, err := runVerify(t, hk.Bytes(), args[0], args[1], args[2])
		require.NoError(err, name)
		require.False(ok, name)
	}
}

// A malformed public key is an error.
func TestVerifyPrecompileBadKey(t *testing.T) {
	_, err := runVerify(t, []byte{0x01, 0x02}, []byte("m"), make([]byte, chameleon.RandomnessLen), make([]byte, chameleon.DigestLen))
	require.Error(t, err)
}

// Not enough gas is an error and nothing is computed.
func TestVerifyPrecompileOutOfGas(t *testing.T) {
	hk, _, err := chameleon.KeyGen()
	require.NoError(t, err)
	digest, r, err := chameleon.Hash(hk, []byte("m"))
	require.NoError(t, err)
	input, err := PackVerify(hk.Bytes(), []byte("m"), r, digest)
	require.NoError(t, err)
	_, _, err = ChameleonHashPrecompile.Run(nil, common.Address{}, ContractAddress, input, verifyGasCost-1, false)
	require.Error(t, err)
}
