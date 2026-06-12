// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package customtypes

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core/types"
	"github.com/ava-labs/libevm/rlp"
	"github.com/stretchr/testify/require"

	"github.com/ava-labs/avalanchego/utils"
	"github.com/ava-labs/avalanchego/vms/evm/acp226"
)

// Builds a test header with all the optional fields set, like a real block
// with all the upgrades active. initial is the value to put in
// InitialTxHash, nil means the field is not set.
// Note: we can't test InitialTxHash set while an earlier optional field is
// nil, because rlpgen encodes the nil one as an empty string and then the
// decoder refuses it for *common.Hash. It's a limit of rlpgen, in practice
// it never happens because all the upgrades are active.
func initialTxHashFixtureHeader(initial *common.Hash) (*types.Header, *HeaderExtra) {
	beaconRoot := common.Hash{0x77}
	h := &types.Header{
		ParentHash:       common.Hash{0xaa},
		UncleHash:        common.Hash{0xbb},
		Coinbase:         common.Address{0xcc},
		Root:             common.Hash{0xdd},
		TxHash:           common.Hash{0xee},
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
	extra := &HeaderExtra{
		BlockGasCost:     big.NewInt(10),
		TimeMilliseconds: utils.PointerTo[uint64](11),
		MinDelayExcess:   utils.PointerTo(acp226.DelayExcess(12)),
		InitialTxHash:    initial,
	}
	return WithHeaderExtra(h, extra), extra
}

// Encode + decode a header with RLP and check that InitialTxHash is still
// there with the same value.
func TestInitialTxHashRLPRoundTrip(t *testing.T) {
	t.Parallel()

	want := common.Hash{0x42, 0x42, 0x42}
	header, _ := initialTxHashFixtureHeader(&want)

	encoded, err := rlp.EncodeToBytes(header)
	require.NoError(t, err, "rlp.EncodeToBytes")

	got := new(types.Header)
	require.NoError(t, rlp.DecodeBytes(encoded, got), "rlp.DecodeBytes")

	gotExtra := GetHeaderExtra(got)
	require.NotNil(t, gotExtra.InitialTxHash, "InitialTxHash dropped during RLP round-trip")
	require.Equal(t, want, *gotExtra.InitialTxHash, "InitialTxHash mismatch after RLP round-trip")
}

// Same as the RLP test but with JSON, which is what the RPC API uses.
func TestInitialTxHashJSONRoundTrip(t *testing.T) {
	t.Parallel()

	want := common.Hash{0x99, 0x88, 0x77}
	header, _ := initialTxHashFixtureHeader(&want)

	encoded, err := json.Marshal(header)
	require.NoError(t, err, "json.Marshal")

	got := new(types.Header)
	require.NoError(t, json.Unmarshal(encoded, got), "json.Unmarshal")

	gotExtra := GetHeaderExtra(got)
	require.NotNil(t, gotExtra.InitialTxHash, "InitialTxHash dropped during JSON round-trip")
	require.Equal(t, want, *gotExtra.InitialTxHash, "InitialTxHash mismatch after JSON round-trip")
}

// Two headers that differ only in InitialTxHash must have different
// hashes, so the field is really part of the block hash. The dual-link
// verification needs this.
func TestInitialTxHashAffectsBlockHash(t *testing.T) {
	t.Parallel()

	a := common.Hash{0x01}
	b := common.Hash{0x02}

	headerA, _ := initialTxHashFixtureHeader(&a)
	headerB, _ := initialTxHashFixtureHeader(&b)

	hashA := headerA.Hash()
	hashB := headerB.Hash()
	require.NotEqual(t, hashA, hashB,
		"changing InitialTxHash must change the block hash (it is part of the RLP encoding hashed by Header.Hash())")
}

// A header without InitialTxHash (like the blocks made before the field
// existed) must decode with the field at nil and keep the same hash, so we
// don't break the old blocks.
func TestInitialTxHashLegacyDecode(t *testing.T) {
	t.Parallel()

	header, _ := initialTxHashFixtureHeader(nil)

	encoded, err := rlp.EncodeToBytes(header)
	require.NoError(t, err, "rlp.EncodeToBytes")

	got := new(types.Header)
	require.NoError(t, rlp.DecodeBytes(encoded, got), "rlp.DecodeBytes")

	gotExtra := GetHeaderExtra(got)
	require.Nil(t, gotExtra.InitialTxHash,
		"a header encoded without InitialTxHash must decode with InitialTxHash == nil")

	hashWithoutField := header.Hash()
	hashRoundTripped := got.Hash()
	require.Equal(t, hashWithoutField, hashRoundTripped,
		"hash must be stable across encode/decode when InitialTxHash is absent")
}
