// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"context"

	"github.com/ava-labs/libevm/common"

	ethtypes "github.com/ava-labs/libevm/core/types"
)

// Policy decides if the redaction of a block is approved. The real one checks
// the stored aggregated BLS proof against the validator set quorum, which needs
// a context to look up the validator set.
type Policy interface {
	Approved(ctx context.Context, parent *ethtypes.Header) bool
}

// alwaysApprove is the stub policy: it accepts every redaction.
type alwaysApprove struct{}

func (alwaysApprove) Approved(context.Context, *ethtypes.Header) bool { return true }

// DefaultPolicy is what ValidParentLink uses until a real policy is wired in.
var DefaultPolicy Policy = alwaysApprove{}

// ValidParentLink checks the child -> parent link with the default policy.
func ValidParentLink(ctx context.Context, childParentHash common.Hash, parent *ethtypes.Header) bool {
	return ValidParentLinkWithPolicy(ctx, childParentHash, parent, DefaultPolicy)
}

// ValidParentLinkWithPolicy is valid if the child points to the normal hash
// (new link), or to the old link when the parent was redacted and the policy
// approves it.
func ValidParentLinkWithPolicy(ctx context.Context, childParentHash common.Hash, parent *ethtypes.Header, policy Policy) bool {
	if childParentHash == NewLink(parent) {
		return true
	}
	return childParentHash == OldLink(parent) && policy.Approved(ctx, parent)
}
