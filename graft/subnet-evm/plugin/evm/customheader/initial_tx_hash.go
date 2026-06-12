// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package customheader

import (
	"github.com/ava-labs/libevm/common"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/params/extras"
)

// InitialTxHash returns the value to put in the InitialTxHash header field:
// a copy of the tx root from Granite on, nil before. In pre-Granite blocks
// the optional header fields before InitialTxHash can be nil and their RLP
// placeholders would not decode (rlpgen limit, see the note in customtypes).
func InitialTxHash(config *extras.ChainConfig, txHash common.Hash, timestamp uint64) *common.Hash {
	if config.IsGranite(timestamp) {
		return &txHash
	}
	return nil
}
