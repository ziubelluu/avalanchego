// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package core

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestReopenAfterUncleanShutdownWithRedactedTip: the tip gets redacted, then
// the node dies without writing its state to disk. On restart the chain has to
// come back without re-executing the redacted block.
func TestReopenAfterUncleanShutdownWithRedactedTip(t *testing.T) {
	c := setupTipChain(t)
	c.redactTip(t)
	oldLink := c.tip.Hash()

	// Like TestPruningBlockChainUngracefulShutdown: Stop without letting the
	// state manager write the last state, as if the process was killed.
	c.bc.stateManager = &wrappedStateManager{TrieWriter: c.bc.stateManager}
	c.bc.Stop()

	bc2, err := createBlockChain(c.db, DefaultCacheConfig, c.gspec, oldLink)
	require.NoError(t, err, "the chain must reopen after an unclean shutdown with a redacted tip")
	defer bc2.Stop()
	bc2.SetRedactionPolicy(c.committee.policy(c.db))

	got := bc2.GetBlockByHash(oldLink)
	require.NotNil(t, got)
	require.Empty(t, got.Transactions()[0].Data(), "the tip is still redacted")
	require.NoError(t, bc2.ValidateCanonicalChain())

	// and the chain goes on: the child gets in and accepted
	require.NoError(t, bc2.InsertBlock(c.child))
	require.NoError(t, bc2.Accept(c.child))
	bc2.DrainAcceptorQueue()
}
