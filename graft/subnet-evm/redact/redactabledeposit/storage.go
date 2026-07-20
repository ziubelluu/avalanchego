// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redactabledeposit

import (
	"math/big"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core/state"
	"github.com/ava-labs/libevm/crypto"
)

// These slots must match the order the variables are declared in
// RedactableDeposit.sol:
//
//	mapping(bytes32 => bytes) private digests;  // slot 0
//	bytes public authorityKey;                  // slot 1
const (
	digestsMappingSlot = 0
	authorityKeySlot   = 1
)

// GetDigest reads the digest committed for [id] from the contract's storage
// (nil if there's none).
func GetDigest(statedb *state.StateDB, addr common.Address, id common.Hash) []byte {
	return readSolidityBytes(statedb, addr, mappingValueSlot(id, digestsMappingSlot))
}

// GetPublicKey reads the authority public key from the contract's storage
// (nil if there's none).
func GetPublicKey(statedb *state.StateDB, addr common.Address) []byte {
	return readSolidityBytes(statedb, addr, common.BigToHash(big.NewInt(authorityKeySlot)))
}

// mappingValueSlot gives the slot where Solidity stores mapping[key]:
// keccak256(key ++ slot).
func mappingValueSlot(key common.Hash, slot int64) common.Hash {
	buf := make([]byte, 64)
	copy(buf[0:32], key.Bytes())
	copy(buf[32:64], common.BigToHash(big.NewInt(slot)).Bytes())
	return crypto.Keccak256Hash(buf)
}

// readSolidityBytes reads a Solidity `bytes` value at [slot]. Solidity stores it
// two ways (short if <32 bytes, long otherwise), so we handle both.
func readSolidityBytes(statedb *state.StateDB, addr common.Address, slot common.Hash) []byte {
	head := statedb.GetState(addr, slot)
	// Lowest bit: 0 = short encoding, 1 = long encoding.
	if head[31]&1 == 0 {
		length := int(head[31] / 2)
		if length == 0 {
			return nil
		}
		out := make([]byte, length)
		copy(out, head[:length])
		return out
	}

	lengthBig := new(big.Int).SetBytes(head[:])
	lengthBig.Sub(lengthBig, big.NewInt(1))
	lengthBig.Rsh(lengthBig, 1)
	length := int(lengthBig.Int64())
	if length == 0 {
		return nil
	}

	out := make([]byte, 0, length)
	start := new(big.Int).SetBytes(crypto.Keccak256Hash(slot.Bytes()).Bytes())
	for i := 0; len(out) < length; i++ {
		wordSlot := common.BigToHash(new(big.Int).Add(start, big.NewInt(int64(i))))
		word := statedb.GetState(addr, wordSlot)
		out = append(out, word[:]...)
	}
	return out[:length]
}
