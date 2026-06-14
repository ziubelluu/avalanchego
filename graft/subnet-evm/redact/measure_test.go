// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"testing"

	"github.com/ava-labs/libevm/core/rawdb"
	"github.com/ava-labs/libevm/core/types"
	"github.com/stretchr/testify/require"

	"github.com/ava-labs/avalanchego/utils/crypto/bls"
)

// TestMeasureProofSize reports the serialized proof size as the committee grows.
// The aggregated BLS signature is constant (bls.SignatureLen); only the signer
// bitset grows, ~1 bit per validator, so the proof stays small.
func TestMeasureProofSize(t *testing.T) {
	t.Logf("%-10s %-9s %-12s %-10s %-8s", "committee", "signers", "proofBytes", "bitset", "aggSig")
	for _, n := range []int{1, 4, 16, 64, 128} {
		_, byIndex := makeCommittee(t, n)
		indices := make([]int, n)
		for i := range indices {
			indices[i] = i
		}
		proof := signProof(t, sampleProposal(), byIndex, indices...)
		raw, err := proof.Bytes()
		require.NoError(t, err)

		// The aggregate signature is always a single fixed-size BLS signature.
		require.Len(t, proof.AggSignature, bls.SignatureLen)

		t.Logf("%-10d %-9d %-12d %-10d %-8d", n, n, len(raw), len(proof.SignerBitSet), len(proof.AggSignature))
	}
}

// BenchmarkAppendBlockOnly is the baseline append: write a (redacted) block's
// header and body, without any redaction proof.
func BenchmarkAppendBlockOnly(b *testing.B) {
	block := types.NewBlockWithHeader(sealedHeader())
	hash := block.Hash()
	db := rawdb.NewMemoryDatabase()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := Persist(db, hash, block); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAppendBlockWithProof appends the same block plus its redaction proof,
// so the delta versus BenchmarkAppendBlockOnly is the marginal cost of storing
// the proof.
func BenchmarkAppendBlockWithProof(b *testing.B) {
	block := types.NewBlockWithHeader(sealedHeader())
	hash := block.Hash()

	_, byIndex := makeCommittee(b, 16)
	proof := signProof(b, sampleProposal(), byIndex, 0)
	proofBytes, err := proof.Bytes()
	require.NoError(b, err)

	db := rawdb.NewMemoryDatabase()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := Persist(db, hash, block); err != nil {
			b.Fatal(err)
		}
		if err := WriteRedactionProof(db, hash, proofBytes); err != nil {
			b.Fatal(err)
		}
	}
}
