// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"fmt"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/crypto"
	"github.com/ava-labs/libevm/rlp"
)

// Proposal is what the committee votes on: redact OriginalHash so its tx root
// becomes NewTxHash, checked at PChainHeight. RedactedIndices are the changed
// positions; signed too, so the committee says exactly what was redacted.
type Proposal struct {
	OriginalHash    common.Hash
	NewTxHash       common.Hash
	PChainHeight    uint64
	RedactedIndices []uint64
}

// String returns a human-readable summary of the proposal.
func (p *Proposal) String() string {
	return fmt.Sprintf("Proposal{originalHash: %s, newTxHash: %s, pChainHeight: %d, redactedIndices: %v}",
		p.OriginalHash, p.NewTxHash, p.PChainHeight, p.RedactedIndices)
}

// Bytes is the RLP encoding that the validators sign over.
func (p *Proposal) Bytes() []byte {
	b, err := rlp.EncodeToBytes(p)
	if err != nil {
		panic(err)
	}
	return b
}

// Hash is the keccak256 of the bytes. This is the vote message.
func (p *Proposal) Hash() common.Hash {
	return crypto.Keccak256Hash(p.Bytes())
}
