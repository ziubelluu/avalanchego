// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chameleonhash

import (
	_ "embed"
	"errors"
	"fmt"

	"github.com/ava-labs/libevm/common"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/precompile/contract"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact/chameleon"
)

//go:embed IChameleonHash.abi
var ChameleonHashRawABI string

// ChameleonHashABI is the parsed interface of the precompile.
var ChameleonHashABI = contract.ParseABI(ChameleonHashRawABI)

// hashGasCost is the gas for one chameleon Hash (two point multiplications + a hash).
var hashGasCost uint64 = 200_000

var errInvalidInput = errors.New("chameleonhash: failed to unpack input")

// ChameleonHashPrecompile is the singleton stateful precompiled contract.
var ChameleonHashPrecompile = createChameleonHashPrecompile()

func createChameleonHashPrecompile() contract.StatefulPrecompiledContract {
	abiFunctionMap := map[string]contract.RunStatefulPrecompileFunc{
		"hash": hashFn,
	}
	functions := make([]*contract.StatefulPrecompileFunction, 0, len(abiFunctionMap))
	for name, fn := range abiFunctionMap {
		method, ok := ChameleonHashABI.Methods[name]
		if !ok {
			panic(fmt.Errorf("given method (%s) does not exist in the ABI", name))
		}
		functions = append(functions, contract.NewStatefulPrecompileFunction(method.ID, fn))
	}
	statefulContract, err := contract.NewStatefulPrecompileContract(nil, functions)
	if err != nil {
		panic(err)
	}
	return statefulContract
}

// hashFn computes CH(m, r) under public key hk. Pure function: no state access.
//
//nolint:revive // unused params are part of RunStatefulPrecompileFunc signature
func hashFn(
	accessibleState contract.AccessibleState,
	caller common.Address,
	self common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) (ret []byte, remainingGas uint64, err error) {
	if remainingGas, err = contract.DeductGas(suppliedGas, hashGasCost); err != nil {
		return nil, 0, err
	}

	hk, m, r, err := UnpackHashInput(input)
	if err != nil {
		return nil, remainingGas, err
	}
	pk, err := chameleon.PublicKeyFromBytes(hk)
	if err != nil {
		return nil, remainingGas, err
	}

	digest := chameleon.Hash(pk, m, r)
	packed, err := PackHashOutput(digest)
	if err != nil {
		return nil, remainingGas, err
	}
	return packed, remainingGas, nil
}

// PackHash builds the hash() calldata (including the 4-byte selector).
func PackHash(hk, m, r []byte) ([]byte, error) {
	return ChameleonHashABI.Pack("hash", hk, m, r)
}

// UnpackHashInput decodes hash() calldata that excludes the 4-byte selector.
func UnpackHashInput(input []byte) (hk, m, r []byte, err error) {
	args, err := ChameleonHashABI.Methods["hash"].Inputs.Unpack(input)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(args) != 3 {
		return nil, nil, nil, errInvalidInput
	}
	var ok bool
	if hk, ok = args[0].([]byte); !ok {
		return nil, nil, nil, errInvalidInput
	}
	if m, ok = args[1].([]byte); !ok {
		return nil, nil, nil, errInvalidInput
	}
	if r, ok = args[2].([]byte); !ok {
		return nil, nil, nil, errInvalidInput
	}
	return hk, m, r, nil
}

// PackHashOutput ABI-encodes a digest as hash() return data.
func PackHashOutput(digest []byte) ([]byte, error) {
	return ChameleonHashABI.PackOutput("hash", digest)
}

// UnpackHashOutput decodes hash() return data into the raw digest bytes.
func UnpackHashOutput(output []byte) ([]byte, error) {
	res, err := ChameleonHashABI.Unpack("hash", output)
	if err != nil {
		return nil, err
	}
	digest, ok := res[0].([]byte)
	if !ok {
		return nil, errInvalidInput
	}
	return digest, nil
}
