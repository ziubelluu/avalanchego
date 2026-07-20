// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"context"
	"errors"

	"github.com/ava-labs/libevm/crypto"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact/chameleon"
)

var (
	// no vote -> no forge: having the trapdoor isn't enough, the committee must approve.
	ErrForgeNotApproved = errors.New("redact: forge refused, committee vote not approved")
	// the new blob isn't the one the committee approved.
	ErrForgeBlobMismatch = errors.New("redact: replacement blob does not match the approved proposal")
)

// Forger makes the chameleon collision for an approved redaction. It keeps the
// two things you need separate:
//   - the vote (an approval from the committee), and
//   - the trapdoor (the authority's local secret).
//
// You can only forge once the committee approves; the trapdoor alone is useless.
type Forger struct {
	approver StateApprover
	trapdoor chameleon.Trapdoor
}

// NewForger builds a Forger from the committee approver and the trapdoor.
// The trapdoor comes from a local secret (see chameleon.LoadTrapdoorEnv), never
// from chain.
func NewForger(approver StateApprover, trapdoor chameleon.Trapdoor) *Forger {
	return &Forger{approver: approver, trapdoor: trapdoor}
}

// NewForgerFromEnv is like NewForger but loads the trapdoor from an env var.
// It fails if the var is missing, so only the authority's node (which sets it)
// can forge.
func NewForgerFromEnv(approver StateApprover, envVar string) (*Forger, error) {
	tk, err := chameleon.LoadTrapdoorEnv(envVar)
	if err != nil {
		return nil, err
	}
	return NewForger(approver, tk), nil
}

// Forge returns r' so that CH(blobPrime, r') == CH(blob, r), but only if the
// committee approved [sp]. No approved vote -> ErrForgeNotApproved (and the
// trapdoor is never touched). Wrong replacement blob -> ErrForgeBlobMismatch.
// The digest in state doesn't change.
func (f *Forger) Forge(ctx context.Context, sp *StateProposal, blob, r, blobPrime []byte) (rPrime []byte, err error) {
	if f.approver == nil || sp == nil || !f.approver.ApprovedState(ctx, sp) {
		return nil, ErrForgeNotApproved
	}
	if crypto.Keccak256Hash(blobPrime) != sp.NewBlobHash {
		return nil, ErrForgeBlobMismatch
	}
	return chameleon.Forge(f.trapdoor, blob, r, blobPrime)
}
