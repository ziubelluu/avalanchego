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
	require.True(t, ValidParentLinkWithPolicy(t.Context(), NewLink(parent), parent, DefaultPolicy))
}

// Redacted parent: the child still points to the original hash (old link).
// This is about the link itself, so every redaction is allowed here.
func TestValidParentLinkOldLinkAfterRedaction(t *testing.T) {
	t.Parallel()

	parent := sealedHeader()
	childParentHash := parent.Hash() // link saved by the child before the redaction

	parent.TxHash = common.Hash{0x12, 0x34} // simulate the redaction

	require.NotEqual(t, childParentHash, NewLink(parent)) // new link is broken
	require.True(t, ValidParentLinkWithPolicy(t.Context(), childParentHash, parent, AllowAllForTesting))
}

// With no policy set the old link of a redacted parent is not accepted, the
// normal link still is.
func TestValidParentLinkDefaultRejectsOldLink(t *testing.T) {
	t.Parallel()

	parent := sealedHeader()
	childParentHash := parent.Hash()

	parent.TxHash = common.Hash{0x12, 0x34}

	require.False(t, ValidParentLinkWithPolicy(t.Context(), childParentHash, parent, DefaultPolicy))
	require.True(t, ValidParentLinkWithPolicy(t.Context(), NewLink(parent), parent, DefaultPolicy))
}

// A hash that matches neither link must be rejected.
func TestValidParentLinkWrongHash(t *testing.T) {
	t.Parallel()

	parent := sealedHeader()
	require.False(t, ValidParentLinkWithPolicy(t.Context(), common.Hash{0xde, 0xad}, parent, DefaultPolicy))
}

// A rejecting policy blocks the old link, but the new link is always fine.
func TestValidParentLinkWithPolicyReject(t *testing.T) {
	t.Parallel()

	parent := sealedHeader()
	childParentHash := parent.Hash()

	parent.TxHash = common.Hash{0x12, 0x34}

	require.False(t, ValidParentLinkWithPolicy(t.Context(), childParentHash, parent, rejectPolicy{}))
	require.True(t, ValidParentLinkWithPolicy(t.Context(), NewLink(parent), parent, rejectPolicy{}))
}
