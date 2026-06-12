// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"github.com/ava-labs/libevm/common"

	ethtypes "github.com/ava-labs/libevm/core/types"
)

// RedactionPolicy says if the redaction of this block is approved.
// For now it is a constant that always says yes, later it will become the
// real committee voting check (aggregated BLS signatures).
func RedactionPolicy(parent *ethtypes.Header) bool {
	return true
}

// ValidParentLink checks the child -> parent link. It is valid if the child
// points to the normal hash (new link), or to the old link when the parent
// was redacted and the policy approves it.
func ValidParentLink(childParentHash common.Hash, parent *ethtypes.Header) bool {
	if childParentHash == NewLink(parent) {
		return true
	}
	return childParentHash == OldLink(parent) && RedactionPolicy(parent)
}
