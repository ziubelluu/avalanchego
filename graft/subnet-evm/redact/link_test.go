// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"math/big"
	"os"
	"testing"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core/types"
	"github.com/stretchr/testify/require"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/plugin/evm/customtypes"
	"github.com/ava-labs/avalanchego/utils"
	"github.com/ava-labs/avalanchego/vms/evm/acp226"
)

func TestMain(m *testing.M) {
	customtypes.Register()
	os.Exit(m.Run())
}

// sealedHeader builds a header like a freshly mined one: all optional fields
// set and InitialTxHash == TxHash.
func sealedHeader() *types.Header {
	txHash := common.Hash{0xee}
	beaconRoot := common.Hash{0x77}
	h := &types.Header{
		ParentHash:       common.Hash{0xaa},
		UncleHash:        common.Hash{0xbb},
		Coinbase:         common.Address{0xcc},
		Root:             common.Hash{0xdd},
		TxHash:           txHash,
		ReceiptHash:      common.Hash{0xff},
		Difficulty:       big.NewInt(1),
		Number:           big.NewInt(2),
		GasLimit:         3,
		GasUsed:          4,
		Time:             5,
		Extra:            []byte{0x06},
		BaseFee:          big.NewInt(7),
		BlobGasUsed:      utils.PointerTo[uint64](8),
		ExcessBlobGas:    utils.PointerTo[uint64](9),
		ParentBeaconRoot: &beaconRoot,
	}
	return customtypes.WithHeaderExtra(h, &customtypes.HeaderExtra{
		BlockGasCost:     big.NewInt(10),
		TimeMilliseconds: utils.PointerTo[uint64](11),
		MinDelayExcess:   utils.PointerTo(acp226.DelayExcess(12)),
		InitialTxHash:    &txHash,
	})
}

// Block never redacted -> the two links must be equal.
func TestOldLinkEqualsNewLinkOnUneditedBlock(t *testing.T) {
	t.Parallel()

	h := sealedHeader()
	require.Equal(t, NewLink(h), OldLink(h))
}

// After a redaction (TxHash changes, InitialTxHash stays) OldLink must still
// give the original hash, while NewLink diverges.
func TestOldLinkRecoversOriginalHashAfterRedaction(t *testing.T) {
	t.Parallel()

	h := sealedHeader()
	originalHash := h.Hash()

	h.TxHash = common.Hash{0x12, 0x34} // simulate the redaction

	require.Equal(t, originalHash, OldLink(h))
	require.NotEqual(t, OldLink(h), NewLink(h))
	require.Equal(t, h.Hash(), NewLink(h))
}

// Old blocks have no InitialTxHash: OldLink falls back to the normal hash.
func TestOldLinkLegacyHeader(t *testing.T) {
	t.Parallel()

	h := sealedHeader()
	customtypes.GetHeaderExtra(h).InitialTxHash = nil

	require.Equal(t, NewLink(h), OldLink(h))
}

// OldLink must not modify the header it gets.
func TestOldLinkDoesNotMutateInput(t *testing.T) {
	t.Parallel()

	h := sealedHeader()
	h.TxHash = common.Hash{0x12, 0x34} // different from InitialTxHash

	hashBefore := h.Hash()
	txHashBefore := h.TxHash

	_ = OldLink(h)

	require.Equal(t, txHashBefore, h.TxHash)
	require.Equal(t, hashBefore, h.Hash())
}
