// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redactabledeposit

import (
	"bytes"
	"errors"

	"github.com/ava-labs/libevm/core/state"
	"github.com/ava-labs/libevm/core/types"
	"github.com/ava-labs/libevm/crypto"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact/chameleon"
)

var (
	errCalldataDigestMismatch = errors.New("redactabledeposit: calldata digest does not match committed digest")
	errOpeningMismatch        = errors.New("redactabledeposit: opening does not commit to digest: (blob, r) does not open D")
	errStoreNotFound          = errors.New("redactabledeposit: the block has no store tx for the approved deposit")
	errDigestNotApproved      = errors.New("redactabledeposit: the store tx digest is not the approved one")
	errContentNotApproved     = errors.New("redactabledeposit: the content is not the one the committee approved")
)

// VerifyRedactedBlock checks every store call in [block]: if its target contract
// has a committed digest for that id, then the calldata digest must match it and
// (blob, r) must open it (using the contract's public key). The contract
// address comes from the tx recipient, so it works for ANY deposit contract.
//
// With a proposal it also ties the block to what the committee voted: the store
// tx for that deposit must be there, with the approved digest and a content
// whose keccak256 is NewBlobHash. It returns the position of that tx, so the
// chain knows exactly which position was redacted.
//
// Plug it in with BlockChain.SetRedactionContentVerifier: a redacted block whose
// new (blob, r) no longer matches D gets rejected at validation.
func VerifyRedactedBlock(block *types.Block, statedb *state.StateDB, sp *redact.StateProposal) ([]uint64, error) {
	if err := verifyOpenings(block, statedb); err != nil {
		return nil, err
	}
	if sp == nil {
		return nil, nil
	}

	idx, tx, ok := findStoreTx(block, sp.DepositAddr, sp.ID)
	if !ok {
		return nil, errStoreNotFound
	}
	_, blob, _, digest, err := UnpackStoreInput(tx.Data()[len(storeSelector):])
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(digest, sp.Digest) {
		return nil, errDigestNotApproved
	}
	if crypto.Keccak256Hash(blob) != sp.NewBlobHash {
		return nil, errContentNotApproved
	}
	return []uint64{uint64(idx)}, nil
}

// verifyOpenings checks that every store call in the block still opens the
// digest committed for it.
func verifyOpenings(block *types.Block, statedb *state.StateDB) error {
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
