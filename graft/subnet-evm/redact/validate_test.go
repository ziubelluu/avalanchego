// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"testing"

	"github.com/ava-labs/libevm/common"
	"github.com/stretchr/testify/require"
)

// Normal case: child points to the standard hash of the parent.
func TestValidParentLinkNewLink(t *testing.T) {
	t.Parallel()

	parent := sealedHeader()
	require.True(t, ValidParentLink(NewLink(parent), parent))
}

// Redacted parent: the child still points to the original hash (old link),
// accepted because the stub policy approves everything.
func TestValidParentLinkOldLinkAfterRedaction(t *testing.T) {
	t.Parallel()

	parent := sealedHeader()
	childParentHash := parent.Hash() // link saved by the child before the redaction

	parent.TxHash = common.Hash{0x12, 0x34} // simulate the redaction

	require.NotEqual(t, childParentHash, NewLink(parent)) // new link is broken
	require.True(t, ValidParentLink(childParentHash, parent))
}

// A hash that matches neither link must be rejected.
func TestValidParentLinkWrongHash(t *testing.T) {
	t.Parallel()

	parent := sealedHeader()
	require.False(t, ValidParentLink(common.Hash{0xde, 0xad}, parent))
}
