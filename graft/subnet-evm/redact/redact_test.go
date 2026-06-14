// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"testing"

	"github.com/ava-labs/libevm/core/rawdb"
	"github.com/stretchr/testify/require"
)

// Our headerKey must match the key libevm uses internally. We write a header
// with rawdb.WriteHeader (which keys by header.Hash()) and check that reading
// at our key gives the same bytes.
func TestHeaderKeyMatchesLibevm(t *testing.T) {
	t.Parallel()

	db := rawdb.NewMemoryDatabase()
	h := sealedHeader()
	rawdb.WriteHeader(db, h)

	want := rawdb.ReadHeaderRLP(db, h.Hash(), h.Number.Uint64())
	require.NotEmpty(t, want)

	got, err := db.Get(headerKey(h.Number.Uint64(), h.Hash()))
	require.NoError(t, err)
	require.Equal(t, []byte(want), got)
}
