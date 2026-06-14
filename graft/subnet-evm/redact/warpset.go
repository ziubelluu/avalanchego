// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"context"
	"fmt"

	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/snow/validators"
)

// NewWarpSetFunc adapts a validators.State to a WarpSetFunc for one subnet: it
// picks that subnet's canonical validator set at the requested P-Chain height.
// The VM builds this closing over vm.ctx.ValidatorState and its SubnetID.
func NewWarpSetFunc(state validators.State, subnetID ids.ID) WarpSetFunc {
	return func(ctx context.Context, pChainHeight uint64) (validators.WarpSet, error) {
		sets, err := state.GetWarpValidatorSets(ctx, pChainHeight)
		if err != nil {
			return validators.WarpSet{}, err
		}
		ws, ok := sets[subnetID]
		if !ok {
			return validators.WarpSet{}, fmt.Errorf("no validator set for subnet %s at height %d", subnetID, pChainHeight)
		}
		return ws, nil
	}
}
