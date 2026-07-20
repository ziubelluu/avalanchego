// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redactabledeposit

import (
	"bytes"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core/types"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact"
)

// FindStoreTx looks in [block] for the store tx that deposited [id] into the
// contract at [depositAddr].
func FindStoreTx(block *types.Block, depositAddr common.Address, id common.Hash) (*types.Transaction, bool) {
	selector := storeSelector
	for _, tx := range block.Transactions() {
		if tx.To() == nil || *tx.To() != depositAddr {
			continue
		}
		data := tx.Data()
		if len(data) < len(selector) || !bytes.Equal(data[:len(selector)], selector) {
			continue
		}
		gotID, _, _, _, err := UnpackStoreInput(data[len(selector):])
		if err == nil && gotID == id {
			return tx, true
		}
	}
	return nil, false
}

// RebuildRedactedStoreTx makes a copy of [orig] with the new opening
// (newBlob, rPrime) in its calldata, keeping id and digest. It reuses the old
// signature: the redacted tx isn't re-executed, so the authority doesn't need
// the depositor's key.
func RebuildRedactedStoreTx(orig *types.Transaction, newBlob, rPrime []byte) (*types.Transaction, error) {
	newData, err := RedactedStoreCalldata(orig.Data(), newBlob, rPrime)
	if err != nil {
		return nil, err
	}
	return redact.RebuildTxWithData(orig, newData)
}
