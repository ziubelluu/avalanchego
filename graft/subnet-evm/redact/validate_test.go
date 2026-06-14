// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"context"
	"testing"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core/types"
	"github.com/stretchr/testify/require"
)

// rejectPolicy refuses every redaction.
type rejectPolicy struct{}

func (rejectPolicy) Approved(context.Context, *types.Header) bool { return false }

// Normal case: child points to the standard hash of the parent.
func TestValidParentLinkNewLink(t *testing.T) {
	t.Parallel()

	parent := sealedHeader()
	require.True(t, ValidParentLink(context.Background(), NewLink(parent), parent))
}

// Redacted parent: the child still points to the original hash (old link),
// accepted because the stub policy approves everything.
func TestValidParentLinkOldLinkAfterRedaction(t *testing.T) {
	t.Parallel()

	parent := sealedHeader()
	childParentHash := parent.Hash() // link saved by the child before the redaction

	parent.TxHash = common.Hash{0x12, 0x34} // simulate the redaction

	require.NotEqual(t, childParentHash, NewLink(parent)) // new link is broken
	require.True(t, ValidParentLink(context.Background(), childParentHash, parent))
}

// A hash that matches neither link must be rejected.
func TestValidParentLinkWrongHash(t *testing.T) {
	t.Parallel()

	parent := sealedHeader()
	require.False(t, ValidParentLink(context.Background(), common.Hash{0xde, 0xad}, parent))
}

// A rejecting policy blocks the old link, but the new link is always fine.
func TestValidParentLinkWithPolicyReject(t *testing.T) {
	t.Parallel()

	parent := sealedHeader()
	childParentHash := parent.Hash()

	parent.TxHash = common.Hash{0x12, 0x34}

	require.False(t, ValidParentLinkWithPolicy(context.Background(), childParentHash, parent, rejectPolicy{}))
	require.True(t, ValidParentLinkWithPolicy(context.Background(), NewLink(parent), parent, rejectPolicy{}))
}
