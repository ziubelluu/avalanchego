// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package redactabledeposit is the Go side of the RedactableDeposit contract: a
// normal contract that keeps only the chameleon digest in state while (blob, r)
// stay in calldata. It holds the contract ABI/bytecode plus helpers to read the
// committed digest from the contract's storage.
package redactabledeposit

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/ava-labs/libevm/accounts/abi"
	"github.com/ava-labs/libevm/common"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact/chameleon"
)

//go:embed RedactableDeposit.abi
var rawABI string

//go:embed RedactableDeposit.bin
var deployHex string

// ABI is the parsed RedactableDeposit contract interface.
var ABI = mustParseABI(rawABI)

// storeSelector is the 4-byte selector of the store(...) method.
var storeSelector = ABI.Methods["store"].ID

func mustParseABI(s string) abi.ABI {
	parsed, err := abi.JSON(strings.NewReader(s))
	if err != nil {
		panic(err)
	}
	return parsed
}

// DigestLen is the byte length of a chameleon digest (compressed BLS12-381 G1).
const DigestLen = chameleon.DigestLen

var errInvalidInput = errors.New("redactabledeposit: failed to unpack store input")

// DeployCode returns the bytecode to deploy the contract, with the constructor
// argument [hk] (the authority public key) appended.
func DeployCode(hk []byte) ([]byte, error) {
	bin, err := hex.DecodeString(strings.TrimSpace(deployHex))
	if err != nil {
		return nil, err
	}
	args, err := ABI.Pack("", hk) // "" packs the constructor
	if err != nil {
		return nil, err
	}
	return append(bin, args...), nil
}

// PackStore builds store calldata (including the 4-byte selector).
func PackStore(id common.Hash, blob, r, digest []byte) ([]byte, error) {
	return ABI.Pack("store", [32]byte(id), blob, r, digest)
}

// UnpackStoreInput decodes store calldata that excludes the 4-byte selector.
func UnpackStoreInput(input []byte) (id common.Hash, blob, r, digest []byte, err error) {
	args, err := ABI.Methods["store"].Inputs.Unpack(input)
	if err != nil {
		return common.Hash{}, nil, nil, nil, err
	}
	if len(args) != 4 {
		return common.Hash{}, nil, nil, nil, errInvalidInput
	}
	rawID, ok := args[0].([32]byte)
	if !ok {
		return common.Hash{}, nil, nil, nil, errInvalidInput
	}
	if blob, ok = args[1].([]byte); !ok {
		return common.Hash{}, nil, nil, nil, errInvalidInput
	}
	if r, ok = args[2].([]byte); !ok {
		return common.Hash{}, nil, nil, nil, errInvalidInput
	}
	if digest, ok = args[3].([]byte); !ok {
		return common.Hash{}, nil, nil, nil, errInvalidInput
	}
	return common.Hash(rawID), blob, r, digest, nil
}

// RedactedStoreCalldata rebuilds store calldata with the new opening
// (blobPrime, rPrime), keeping the same id and digest.
func RedactedStoreCalldata(origCalldata, blobPrime, rPrime []byte) ([]byte, error) {
	selector := storeSelector
	if len(origCalldata) < len(selector) || !bytes.Equal(origCalldata[:len(selector)], selector) {
		return nil, errInvalidInput
	}
	id, _, _, digest, err := UnpackStoreInput(origCalldata[len(selector):])
	if err != nil {
		return nil, err
	}
	return PackStore(id, blobPrime, rPrime, digest)
}

// PackDigestOf builds digestOf calldata (including the 4-byte selector).
func PackDigestOf(id common.Hash) ([]byte, error) {
	return ABI.Pack("digestOf", [32]byte(id))
}

// UnpackDigestOfOutput decodes digestOf return data into the raw digest bytes.
func UnpackDigestOfOutput(output []byte) ([]byte, error) {
	res, err := ABI.Unpack("digestOf", output)
	if err != nil {
		return nil, err
	}
	digest, ok := res[0].([]byte)
	if !ok {
		return nil, errInvalidInput
	}
	return digest, nil
}
