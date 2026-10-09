// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chameleonhash

import (
	"errors"
	"fmt"

	"github.com/ava-labs/libevm/common"

	_ "embed"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/precompile/contract"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact/chameleon"
)

//go:embed IChameleonHash.abi
var ChameleonHashRawABI string

// ChameleonHashABI is the parsed interface of the precompile.
var ChameleonHashABI = contract.ParseABI(ChameleonHashRawABI)

// verifyGasCost is the gas for one chameleon Verify (a hash-to-curve, six
// scalar multiplications in G1 and a hash). Measured against ecrecover in the
// same process, i7-14700KF, Go 1.25: ecrecover 25.1 us (median of 5), Verify
// 582.6 us (1 KiB message). 582.6 / 25.1 = 23.2 times ecrecover's 3000 gas =
// 69 600, rounded up to 70 000.
var verifyGasCost uint64 = 70_000

var errInvalidInput = errors.New("chameleonhash: failed to unpack input")

// ChameleonHashPrecompile is the singleton stateful precompiled contract.
var ChameleonHashPrecompile = createChameleonHashPrecompile()

func createChameleonHashPrecompile() contract.StatefulPrecompiledContract {
	abiFunctionMap := map[string]contract.RunStatefulPrecompileFunc{
		"verify": verifyFn,
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

// verifyFn checks that (m, r) opens digest under hk. Pure function: no state
// access. A bad opening is a false answer, a bad key is an error.
//
//nolint:revive // unused params are part of RunStatefulPrecompileFunc signature
func verifyFn(
	accessibleState contract.AccessibleState,
	caller common.Address,
	self common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) (ret []byte, remainingGas uint64, err error) {
	if remainingGas, err = contract.DeductGas(suppliedGas, verifyGasCost); err != nil {
		return nil, 0, err
	}

	hk, m, r, digest, err := UnpackVerifyInput(input)
	if err != nil {
		return nil, remainingGas, err
	}
	pk, err := chameleon.PublicKeyFromBytes(hk)
	if err != nil {
		return nil, remainingGas, err
	}

	packed, err := PackVerifyOutput(chameleon.Verify(pk, m, r, digest))
	if err != nil {
		return nil, remainingGas, err
	}
	return packed, remainingGas, nil
}

// PackVerify builds the verify() calldata (including the 4-byte selector).
func PackVerify(hk, m, r, digest []byte) ([]byte, error) {
	return ChameleonHashABI.Pack("verify", hk, m, r, digest)
}

// UnpackVerifyInput decodes verify() calldata that excludes the 4-byte selector.
func UnpackVerifyInput(input []byte) (hk, m, r, digest []byte, err error) {
	args, err := ChameleonHashABI.Methods["verify"].Inputs.Unpack(input)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if len(args) != 4 {
		return nil, nil, nil, nil, errInvalidInput
	}
	var ok bool
	if hk, ok = args[0].([]byte); !ok {
		return nil, nil, nil, nil, errInvalidInput
	}
	if m, ok = args[1].([]byte); !ok {
		return nil, nil, nil, nil, errInvalidInput
	}
	if r, ok = args[2].([]byte); !ok {
		return nil, nil, nil, nil, errInvalidInput
	}
	if digest, ok = args[3].([]byte); !ok {
		return nil, nil, nil, nil, errInvalidInput
	}
	return hk, m, r, digest, nil
}

// PackVerifyOutput ABI-encodes the answer as verify() return data.
func PackVerifyOutput(ok bool) ([]byte, error) {
	return ChameleonHashABI.PackOutput("verify", ok)
}

// UnpackVerifyOutput decodes verify() return data.
func UnpackVerifyOutput(output []byte) (bool, error) {
	res, err := ChameleonHashABI.Unpack("verify", output)
	if err != nil {
		return false, err
	}
	ok, isBool := res[0].(bool)
	if !isBool {
		return false, errInvalidInput
	}
	return ok, nil
}
