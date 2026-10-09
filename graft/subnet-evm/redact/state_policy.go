// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"context"

	"github.com/ava-labs/libevm/common"
)

// StateApprover says whether a redaction (a StateProposal) was approved by the
// committee. The forge needs this: no approval, no collision.
type StateApprover interface {
	ApprovedState(ctx context.Context, sp *StateProposal) bool
}

// approvedProposal approves one proposal only, whose proof the caller has
// already checked. It's what the node gives the forger right after verifying
// the proof it received.
type approvedProposal struct {
	hash common.Hash
}

// NewApprovedProposal returns an approver that says yes to [sp] and nothing else.
func NewApprovedProposal(sp *StateProposal) StateApprover {
	return approvedProposal{hash: sp.Hash()}
}

func (a approvedProposal) ApprovedState(_ context.Context, sp *StateProposal) bool {
	return sp != nil && sp.Hash() == a.hash
}
