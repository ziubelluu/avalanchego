// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/snow/validators"
	"github.com/ava-labs/avalanchego/snow/validators/validatorstest"
)

// The subnet's set at the height is returned.
func TestNewWarpSetFuncReturnsSubnetSet(t *testing.T) {
	t.Parallel()

	subnetID := ids.GenerateTestID()
	want := validators.WarpSet{TotalWeight: 7}
	state := &validatorstest.State{
		T: t,
		GetWarpValidatorSetsF: func(_ context.Context, _ uint64) (map[ids.ID]validators.WarpSet, error) {
			return map[ids.ID]validators.WarpSet{subnetID: want}, nil
		},
	}

	got, err := NewWarpSetFunc(state, subnetID)(context.Background(), 10)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

// No set for our subnet -> error.
func TestNewWarpSetFuncMissingSubnet(t *testing.T) {
	t.Parallel()

	state := &validatorstest.State{
		T: t,
		GetWarpValidatorSetsF: func(_ context.Context, _ uint64) (map[ids.ID]validators.WarpSet, error) {
			return map[ids.ID]validators.WarpSet{ids.GenerateTestID(): {}}, nil
		},
	}

	_, err := NewWarpSetFunc(state, ids.GenerateTestID())(context.Background(), 10)
	require.Error(t, err)
}

// A state error is propagated.
func TestNewWarpSetFuncStateError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("boom")
	state := &validatorstest.State{
		T: t,
		GetWarpValidatorSetsF: func(_ context.Context, _ uint64) (map[ids.ID]validators.WarpSet, error) {
			return nil, wantErr
		},
	}

	_, err := NewWarpSetFunc(state, ids.GenerateTestID())(context.Background(), 10)
	require.ErrorIs(t, err, wantErr)
}
