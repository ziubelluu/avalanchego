// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package customheader

import (
	"testing"

	"github.com/ava-labs/libevm/common"
	"github.com/stretchr/testify/require"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/params/extras"
)

func TestInitialTxHash(t *testing.T) {
	txHash := common.Hash{0xee}

	tests := []struct {
		name     string
		config   *extras.ChainConfig
		expected *common.Hash
	}{
		{
			name:     "pre_granite_returns_nil",
			config:   extras.TestFortunaChainConfig,
			expected: nil,
		},
		{
			name:     "granite_returns_tx_hash_copy",
			config:   extras.TestGraniteChainConfig,
			expected: &txHash,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := InitialTxHash(test.config, txHash, 1000)
			require.Equal(t, test.expected, got)
		})
	}
}
