// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redactabledeposit

import (
	"bytes"
	"errors"

	"github.com/ava-labs/libevm/core/state"
	"github.com/ava-labs/libevm/core/types"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact/chameleon"
)

var (
	errCalldataDigestMismatch = errors.New("redactabledeposit: calldata digest does not match committed digest")
	errOpeningMismatch        = errors.New("redactabledeposit: opening does not commit to digest: CH(blob, r) != D")
)

// VerifyRedactedBlock checks every store call in [block]: if its target contract
// has a committed digest for that id, then the calldata digest must match it and
// CH(blob, r) must equal it (using the contract's public key). The contract
// address comes from the tx recipient, so it works for ANY deposit contract.
//
// Plug it in with BlockChain.SetRedactionContentVerifier: a redacted block whose
// new (blob, r) no longer matches D gets rejected at validation.
func VerifyRedactedBlock(block *types.Block, statedb *state.StateDB) error {
	selector := storeSelector

	for _, tx := range block.Transactions() {
		if tx.To() == nil {
			continue
		}
		data := tx.Data()
		if len(data) < len(selector) || !bytes.Equal(data[:len(selector)], selector) {
			continue
		}
		id, blob, randomness, calldataDigest, err := UnpackStoreInput(data[len(selector):])
		if err != nil {
			continue // not a well-formed store call
		}

		depositAddr := *tx.To()
		committed := GetDigest(statedb, depositAddr, id)
		if committed == nil {
			continue // nothing committed for this id here, so not our deposit
		}

		// It's a real deposit, so check it.
		if !bytes.Equal(calldataDigest, committed) {
			return errCalldataDigestMismatch
		}
		pkBytes := GetPublicKey(statedb, depositAddr)
		if pkBytes == nil {
			continue // no public key published, can't check
		}
		hk, err := chameleon.PublicKeyFromBytes(pkBytes)
		if err != nil {
			return err
		}
		if !chameleon.Verify(hk, blob, randomness, committed) {
			return errOpeningMismatch
		}
	}
	return nil
}
