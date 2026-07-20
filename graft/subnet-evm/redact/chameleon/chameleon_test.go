// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chameleon

import (
	"bytes"
	"testing"
)

// freshRandomness returns a canonical 32-byte scalar to use as r.
func freshRandomness(t *testing.T) []byte {
	t.Helper()
	_, tk, err := KeyGen()
	if err != nil {
		t.Fatalf("KeyGen for randomness: %v", err)
	}
	enc := tk.X.Bytes()
	return enc[:]
}

func TestHashVerifyRoundTrip(t *testing.T) {
	hk, _, err := KeyGen()
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	m := []byte("the original inert blob")
	r := freshRandomness(t)

	digest := Hash(hk, m, r)
	if len(digest) == 0 {
		t.Fatal("empty digest")
	}
	if !Verify(hk, m, r, digest) {
		t.Fatal("Verify(Hash(m, r)) == false, want true")
	}
}

func TestForgeCollision(t *testing.T) {
	hk, tk, err := KeyGen()
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	m := []byte("original blob")
	mPrime := []byte("redacted blob")
	r := freshRandomness(t)

	digest := Hash(hk, m, r)

	rPrime, err := Forge(tk, m, r, mPrime)
	if err != nil {
		t.Fatalf("Forge: %v", err)
	}

	// The collision: the new (m', r') hashes to the SAME digest, so the value
	// committed in state never changes after a redaction.
	if !Verify(hk, mPrime, rPrime, digest) {
		t.Fatal("forged (m', r') does not collide with original digest")
	}
	if !bytes.Equal(Hash(hk, mPrime, rPrime), digest) {
		t.Fatal("Hash(m', r') != Hash(m, r)")
	}
}

func TestForgeIdentityWhenSameMessage(t *testing.T) {
	// Forging towards the same message must leave r unchanged (delta == 0).
	hk, tk, err := KeyGen()
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	m := []byte("same blob")
	r := freshRandomness(t)

	rPrime, err := Forge(tk, m, r, m)
	if err != nil {
		t.Fatalf("Forge: %v", err)
	}
	if !Verify(hk, m, rPrime, Hash(hk, m, r)) {
		t.Fatal("identity forge broke the digest")
	}
}

func TestVerifyFailsWrongKey(t *testing.T) {
	hk, _, err := KeyGen()
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	other, _, err := KeyGen()
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	m := []byte("blob")
	r := freshRandomness(t)

	digest := Hash(hk, m, r)
	if Verify(other, m, r, digest) {
		t.Fatal("Verify accepted a digest under the wrong public key")
	}
}

func TestVerifyFailsTamperedInputs(t *testing.T) {
	hk, _, err := KeyGen()
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	m := []byte("blob")
	r := freshRandomness(t)
	digest := Hash(hk, m, r)

	if Verify(hk, []byte("blob-tampered"), r, digest) {
		t.Fatal("Verify accepted a tampered message")
	}

	rTampered := bytes.Clone(r)
	rTampered[0] ^= 0xFF
	if Verify(hk, m, rTampered, digest) {
		t.Fatal("Verify accepted tampered randomness")
	}

	dTampered := bytes.Clone(digest)
	dTampered[len(dTampered)-1] ^= 0x01
	if Verify(hk, m, r, dTampered) {
		t.Fatal("Verify accepted a tampered digest")
	}
}

func TestForgeWrongTrapdoorNoCollision(t *testing.T) {
	hk, _, err := KeyGen()
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	_, wrongTk, err := KeyGen()
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	m := []byte("original")
	mPrime := []byte("redacted")
	r := freshRandomness(t)
	digest := Hash(hk, m, r)

	rPrime, err := Forge(wrongTk, m, r, mPrime)
	if err != nil {
		t.Fatalf("Forge: %v", err)
	}
	// A forge with the wrong trapdoor must NOT produce a collision.
	if Verify(hk, mPrime, rPrime, digest) {
		t.Fatal("forge with wrong trapdoor still collided")
	}
}

func TestForgeZeroTrapdoorRejected(t *testing.T) {
	var tk Trapdoor // X is zero
	if _, err := Forge(tk, []byte("a"), freshRandomness(t), []byte("b")); err == nil {
		t.Fatal("Forge accepted a zero trapdoor")
	}
}
