// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chameleon

import (
	"bytes"
	"testing"
)

// benchInputs returns a reusable key pair, a 1 KiB blob, randomness and digest.
func benchInputs(tb testing.TB) (PublicKey, Trapdoor, []byte, []byte, []byte) {
	tb.Helper()
	hk, tk, err := KeyGen()
	if err != nil {
		tb.Fatalf("KeyGen: %v", err)
	}
	blob := bytes.Repeat([]byte{0xAB, 0xCD, 0xEF, 0x12}, 256)
	r := bytes.Repeat([]byte{0x07}, 32)
	digest := Hash(hk, blob, r)
	return hk, tk, blob, r, digest
}

func BenchmarkKeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, _, err := KeyGen(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHash(b *testing.B) {
	hk, _, blob, r, _ := benchInputs(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Hash(hk, blob, r)
	}
}

func BenchmarkVerify(b *testing.B) {
	hk, _, blob, r, digest := benchInputs(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !Verify(hk, blob, r, digest) {
			b.Fatal("verify failed")
		}
	}
}

func BenchmarkForge(b *testing.B) {
	hk, tk, blob, r, digest := benchInputs(b)
	blobPrime := []byte{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rPrime, err := Forge(tk, blob, r, blobPrime)
		if err != nil {
			b.Fatal(err)
		}
		_ = rPrime
		_ = hk
		_ = digest
	}
}

// TestMeasureDigestVsBlob compares the digest we keep on state with the raw blob
// size. The digest is always a 48-byte G1 point, so the state footprint stays
// constant no matter how big the blob is.
func TestMeasureDigestVsBlob(t *testing.T) {
	hk, _, _, _, _ := benchInputs(t)
	r := bytes.Repeat([]byte{0x07}, 32)

	t.Logf("%-12s %-12s %-12s", "blobBytes", "digestBytes", "ratio")
	for _, size := range []int{32, 256, 1024, 4096, 65536} {
		blob := bytes.Repeat([]byte{0xAB}, size)
		d := Hash(hk, blob, r)
		if len(d) != DigestLen {
			t.Fatalf("digest len = %d, want %d", len(d), DigestLen)
		}
		t.Logf("%-12d %-12d %-12.5f", size, len(d), float64(len(d))/float64(size))
	}
}
