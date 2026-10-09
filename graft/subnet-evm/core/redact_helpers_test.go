// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package core

import (
	"context"
	"testing"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core/types"
	"github.com/ava-labs/libevm/ethdb"
	"github.com/stretchr/testify/require"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact"
	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/snow/validators"
	"github.com/ava-labs/avalanchego/utils/constants"
	"github.com/ava-labs/avalanchego/utils/crypto/bls"
	"github.com/ava-labs/avalanchego/utils/set"
	"github.com/ava-labs/avalanchego/vms/platformvm/warp"
)

// signTxProof makes the committee members in [indices] sign a tx proposal and
// packs the signatures into a Proof.
func signTxProof(t testing.TB, networkID uint32, sourceChainID ids.ID, p *redact.Proposal, byIndex map[int]bls.Signer, indices ...int) []byte {
	t.Helper()
	msg, err := warp.NewUnsignedMessage(networkID, sourceChainID, p.Bytes())
	require.NoError(t, err)

	signers := set.NewBits()
	sigs := make([]*bls.Signature, 0, len(indices))
	for _, idx := range indices {
		sig, err := byIndex[idx].Sign(msg.Bytes())
		require.NoError(t, err)
		sigs = append(sigs, sig)
		signers.Add(idx)
	}
	aggSig, err := bls.AggregateSignatures(sigs)
	require.NoError(t, err)

	proof := &redact.Proof{Proposal: *p, SignerBitSet: signers.Bytes()}
	copy(proof.AggSignature[:], bls.SignatureToBytes(aggSig))
	raw, err := proof.Bytes()
	require.NoError(t, err)
	return raw
}

// testCommittee is three validators with their BLS keys. The tests use it to
// sign proposals and to build the real policy (quorum 2/3).
type testCommittee struct {
	networkID     uint32
	sourceChainID ids.ID
	ws            validators.WarpSet
	byIndex       map[int]bls.Signer
}

func newTestCommittee(t testing.TB) *testCommittee {
	t.Helper()
	ws, byIndex := buildCommittee(t)
	return &testCommittee{
		networkID:     constants.UnitTestID,
		sourceChainID: ids.GenerateTestID(),
		ws:            ws,
		byIndex:       byIndex,
	}
}

// policy is the real committee policy, reading the proofs from [db].
func (c *testCommittee) policy(db ethdb.KeyValueReader) redact.Policy {
	warpSet := func(context.Context, uint64) (validators.WarpSet, error) { return c.ws, nil }
	return redact.NewCommitteePolicy(db, warpSet, c.networkID, c.sourceChainID, 2, 3)
}

// approve makes the whole committee sign the redaction that turned the block
// under [oldLink] into [redacted], and stores the proof for it.
func (c *testCommittee) approve(t testing.TB, db ethdb.KeyValueWriter, oldLink common.Hash, redacted *types.Block, indices []uint64) {
	t.Helper()
	p := &redact.Proposal{
		OriginalHash:    oldLink,
		NewTxHash:       redacted.TxHash(),
		PChainHeight:    1,
		RedactedIndices: indices,
	}
	raw := signTxProof(t, c.networkID, c.sourceChainID, p, c.byIndex, 0, 1, 2)
	require.NoError(t, redact.WriteRedactionProof(db, oldLink, raw))
}

// blank returns the transactions of [block] with the calldata removed at
// [indices], the same way the VM does it.
func blank(t *testing.T, block *types.Block, indices ...uint64) []*types.Transaction {
	t.Helper()
	out := make([]*types.Transaction, len(block.Transactions()))
	copy(out, block.Transactions())
	for _, i := range indices {
		tx, err := redact.RebuildTxWithData(out[i], nil)
		require.NoError(t, err)
		out[i] = tx
	}
	return out
}
