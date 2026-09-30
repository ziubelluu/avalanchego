// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"github.com/ava-labs/libevm/common"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/plugin/evm/customtypes"

	ethtypes "github.com/ava-labs/libevm/core/types"
)

// NewLink = standard header hash (uses the current TxHash).
func NewLink(h *ethtypes.Header) common.Hash {
	return h.Hash()
}

// OldLink = header hash but with InitialTxHash in place of TxHash, i.e. the
// hash the block had before being redacted. Works on a copy, the input is not
// touched. If InitialTxHash is nil (old blocks) just return the normal hash.
func OldLink(h *ethtypes.Header) common.Hash {
	initialTxHash := customtypes.GetHeaderExtra(h).InitialTxHash
	if initialTxHash == nil {
		return h.Hash()
	}

	orig := ethtypes.CopyHeader(h) // copy keeps the extras too (PostCopy)
	orig.TxHash = *initialTxHash
	return orig.Hash()
}

// IsRedacted says if the block was redacted: TxHash moved away from the tx
// root it was born with. It's a compare of two fields, no hashing, so it's
// cheap enough to run on every block.
func IsRedacted(h *ethtypes.Header) bool {
	initialTxHash := customtypes.GetHeaderExtra(h).InitialTxHash
	return initialTxHash != nil && *initialTxHash != h.TxHash
}
