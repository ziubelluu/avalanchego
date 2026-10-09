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
	digest, rs, err := Hash(hk, blob)
	if err != nil {
		tb.Fatalf("Hash: %v", err)
	}
	return hk, tk, blob, rs, digest
}

func BenchmarkKeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, _, err := KeyGen(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHash(b *testing.B) {
	hk, _, blob, _, _ := benchInputs(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := Hash(hk, blob); err != nil {
			b.Fatal(err)
		}
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
		rPrime, err := Forge(tk, blob, r, blobPrime, digest)
		if err != nil {
			b.Fatal(err)
		}
		_ = rPrime
		_ = hk
	}
}

// TestMeasureDigestVsBlob compares the digest we keep on state with the raw blob
// size. The digest is two compressed G1 points, so always 96 bytes no matter
// how big the blob is.
func TestMeasureDigestVsBlob(t *testing.T) {
	hk, _, _, _, _ := benchInputs(t)

	t.Logf("%-12s %-12s %-12s", "blobBytes", "digestBytes", "ratio")
	for _, size := range []int{32, 256, 1024, 4096, 65536} {
		blob := bytes.Repeat([]byte{0xAB}, size)
		d, _, err := Hash(hk, blob)
		if err != nil {
			t.Fatal(err)
		}
		if len(d) != DigestLen {
			t.Fatalf("digest len = %d, want %d", len(d), DigestLen)
		}
		t.Logf("%-12d %-12d %-12.5f", size, len(d), float64(len(d))/float64(size))
	}
}
