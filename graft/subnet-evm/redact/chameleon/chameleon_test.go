// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chameleon

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"

	blst "github.com/supranational/blst/bindings/go"
)

func keyPair(t *testing.T) (PublicKey, Trapdoor) {
	t.Helper()
	hk, tk, err := KeyGen()
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	return hk, tk
}

// hashOf is Hash with the error checked.
func hashOf(t *testing.T, hk PublicKey, m []byte) (digest, rs []byte) {
	t.Helper()
	digest, rs, err := Hash(hk, m)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	return digest, rs
}

func TestSizes(t *testing.T) {
	hk, tk := keyPair(t)
	digest, rs := hashOf(t, hk, []byte("blob"))
	for name, got := range map[string][2]int{
		"public key": {len(hk.Bytes()), PublicKeyLen},
		"trapdoor":   {len(tk.Bytes()), TrapdoorLen},
		"digest":     {len(digest), DigestLen},
		"randomness": {len(rs), RandomnessLen},
	} {
		if got[0] != got[1] {
			t.Errorf("%s is %d bytes, want %d", name, got[0], got[1])
		}
	}
	if PublicKeyLen != 48 || TrapdoorLen != 32 || DigestLen != 96 || RandomnessLen != 128 {
		t.Fatal("sizes are not the ones of G1 on BLS12-381")
	}
}

func TestHashVerifyRoundTrip(t *testing.T) {
	hk, _ := keyPair(t)
	m := []byte("the original inert blob")
	digest, rs := hashOf(t, hk, m)
	if !Verify(hk, m, rs, digest) {
		t.Fatal("Verify(Hash(m)) == false, want true")
	}
	// empty message too
	d2, rs2 := hashOf(t, hk, nil)
	if !Verify(hk, nil, rs2, d2) || !Verify(hk, []byte{}, rs2, d2) {
		t.Fatal("empty message does not verify")
	}
}

func TestHashIsRandomized(t *testing.T) {
	hk, _ := keyPair(t)
	m := []byte("same blob")
	d1, rs1 := hashOf(t, hk, m)
	d2, rs2 := hashOf(t, hk, m)
	if bytes.Equal(d1, d2) || bytes.Equal(rs1, rs2) {
		t.Fatal("two hashes of the same message came out identical")
	}
}

func TestForgeCollision(t *testing.T) {
	hk, tk := keyPair(t)
	m := []byte("original blob")
	mPrime := []byte("redacted blob")
	digest, rs := hashOf(t, hk, m)

	rsPrime, err := Forge(tk, m, rs, mPrime, digest)
	if err != nil {
		t.Fatalf("Forge: %v", err)
	}
	if len(rsPrime) != RandomnessLen {
		t.Fatalf("forged randomness len = %d, want %d", len(rsPrime), RandomnessLen)
	}
	// The collision: (m', r') opens the SAME digest, so what sits in state
	// never changes after a redaction.
	if !Verify(hk, mPrime, rsPrime, digest) {
		t.Fatal("forged (m', r') does not open the original digest")
	}
	// and the old opening still does too
	if !Verify(hk, m, rs, digest) {
		t.Fatal("the original opening stopped verifying")
	}
}

func TestForgeToEmptyAndSameMessage(t *testing.T) {
	hk, tk := keyPair(t)
	m := []byte("original blob")
	digest, rs := hashOf(t, hk, m)

	rsEmpty, err := Forge(tk, m, rs, []byte{}, digest)
	if err != nil {
		t.Fatalf("Forge to empty: %v", err)
	}
	if !Verify(hk, []byte{}, rsEmpty, digest) {
		t.Fatal("forge to the empty message did not open the digest")
	}

	rsSame, err := Forge(tk, m, rs, m, digest)
	if err != nil {
		t.Fatalf("Forge to same: %v", err)
	}
	if bytes.Equal(rsSame, rs) {
		t.Fatal("forge to the same message gave back the same randomness")
	}
	if !Verify(hk, m, rsSame, digest) {
		t.Fatal("forge to the same message did not verify")
	}
}

func TestForgeIsRandomized(t *testing.T) {
	hk, tk := keyPair(t)
	m := []byte("original")
	mPrime := []byte("redacted")
	digest, rs := hashOf(t, hk, m)
	a, err := Forge(tk, m, rs, mPrime, digest)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Forge(tk, m, rs, mPrime, digest)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two forges gave the same randomness")
	}
	if !Verify(hk, mPrime, a, digest) || !Verify(hk, mPrime, b, digest) {
		t.Fatal("a forge did not verify")
	}
}

// A redaction can be redacted again: forging from a forged opening works,
// and so does forging twice from the same opening.
func TestForgeChained(t *testing.T) {
	hk, tk := keyPair(t)
	m := []byte("v1")
	digest, rs := hashOf(t, hk, m)

	rs2, err := Forge(tk, m, rs, []byte("v2"), digest)
	if err != nil {
		t.Fatal(err)
	}
	rs3, err := Forge(tk, []byte("v2"), rs2, []byte("v3"), digest)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(hk, []byte("v3"), rs3, digest) {
		t.Fatal("chained forge did not open the digest")
	}
	rs3b, err := Forge(tk, m, rs, []byte("v3"), digest)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(hk, []byte("v3"), rs3b, digest) {
		t.Fatal("second forge from the first opening did not open the digest")
	}
}

func TestVerifyFailsWrongKey(t *testing.T) {
	hk, _ := keyPair(t)
	other, _ := keyPair(t)
	m := []byte("blob")
	digest, rs := hashOf(t, hk, m)
	if Verify(other, m, rs, digest) {
		t.Fatal("Verify accepted a digest under the wrong public key")
	}
}

func TestVerifyFailsTamperedInputs(t *testing.T) {
	hk, _ := keyPair(t)
	m := []byte("blob")
	digest, rs := hashOf(t, hk, m)

	if Verify(hk, []byte("blob-tampered"), rs, digest) {
		t.Fatal("Verify accepted a tampered message")
	}
	// each of the four scalars, changed by one in its last byte
	for i := 0; i < 4; i++ {
		bad := bytes.Clone(rs)
		bad[(i+1)*ScalarLen-1] ^= 0x01
		if Verify(hk, m, bad, digest) {
			t.Fatalf("Verify accepted randomness with scalar %d changed", i)
		}
	}
	// the digest: c1 and c2, flipping a bit of the x coordinate
	for _, i := range []int{PointLen - 1, DigestLen - 1} {
		bad := bytes.Clone(digest)
		bad[i] ^= 0x01
		if Verify(hk, m, rs, bad) {
			t.Fatalf("Verify accepted a digest tampered at byte %d", i)
		}
	}
	// a proof for (y, h, m) does not work for another m or another h
	d2, _ := hashOf(t, hk, m)
	if Verify(hk, m, rs, d2) {
		t.Fatal("Verify accepted the proof of one digest for another digest")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	hk, tk := keyPair(t)
	m := []byte("blob")
	digest, rs := hashOf(t, hk, m)

	// a scalar equal to q (the group order) is not reduced
	tooBig := bytes.Clone(rs)
	copy(tooBig[:ScalarLen], Order.FillBytes(make([]byte, ScalarLen)))

	for name, bad := range map[string][]byte{
		"nil":         nil,
		"short":       make([]byte, RandomnessLen-1),
		"long":        make([]byte, RandomnessLen+1),
		"scalar >= q": tooBig,
	} {
		if Verify(hk, m, bad, digest) {
			t.Fatalf("Verify accepted %s randomness", name)
		}
		if _, err := Forge(tk, m, bad, m, digest); err == nil {
			t.Fatalf("Forge accepted %s randomness", name)
		}
	}

	notOnCurve := bytes.Clone(digest)
	notOnCurve[0] = 0x80 | 0x40 // the compressed point at infinity flag plus garbage
	notOnCurve[1] = 0xff
	for name, bad := range map[string][]byte{
		"nil":         nil,
		"short":       digest[:DigestLen-1],
		"not a point": notOnCurve,
		"infinity c1": append(append([]byte{0xc0}, make([]byte, PointLen-1)...), digest[PointLen:]...),
	} {
		if Verify(hk, m, rs, bad) {
			t.Fatalf("Verify accepted %s digest", name)
		}
		if _, err := Forge(tk, m, rs, m, bad); err == nil {
			t.Fatalf("Forge accepted %s digest", name)
		}
	}
}

// A compressed point that is on the curve but not in the prime-order
// subgroup must be refused wherever a point comes in from outside.
func TestRejectsPointOutsideSubgroup(t *testing.T) {
	var outside []byte
	for i := 0; i < 10000 && outside == nil; i++ {
		b := make([]byte, PointLen)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		b[0] = (b[0] & 0x1f) | 0x80 // compressed, not infinity, y sign from bit 5
		var p blst.P1Affine
		if p.Uncompress(b) != nil && !p.InG1() {
			outside = b
		}
	}
	if outside == nil {
		t.Fatal("could not find a curve point outside G1")
	}

	if _, err := PublicKeyFromBytes(outside); err == nil {
		t.Fatal("PublicKeyFromBytes accepted a point outside G1")
	}
	hk, tk := keyPair(t)
	m := []byte("blob")
	digest, rs := hashOf(t, hk, m)
	bad := append(bytes.Clone(outside), digest[PointLen:]...)
	if Verify(hk, m, rs, bad) {
		t.Fatal("Verify accepted a digest with c1 outside G1")
	}
	if _, err := Forge(tk, m, rs, m, bad); err == nil {
		t.Fatal("Forge accepted a digest with c1 outside G1")
	}
}

func TestForgeWrongTrapdoorNoCollision(t *testing.T) {
	hk, _ := keyPair(t)
	_, wrongTk := keyPair(t)
	m := []byte("original")
	mPrime := []byte("redacted")
	digest, rs := hashOf(t, hk, m)

	rsPrime, err := Forge(wrongTk, m, rs, mPrime, digest)
	if err == nil && Verify(hk, mPrime, rsPrime, digest) {
		t.Fatal("forge with the wrong trapdoor still collided")
	}
}

// Forge checks the opening it is given first: a wrong (m, rs, digest) is an
// error, not a forged collision for garbage.
func TestForgeRefusesBadOpening(t *testing.T) {
	hk, tk := keyPair(t)
	digest, rs := hashOf(t, hk, []byte("original"))
	if _, err := Forge(tk, []byte("not the original"), rs, []byte("x"), digest); err == nil {
		t.Fatal("Forge accepted an opening that does not verify")
	}
	other, _ := hashOf(t, hk, []byte("original"))
	if _, err := Forge(tk, []byte("original"), rs, []byte("x"), other); err == nil {
		t.Fatal("Forge accepted a randomness for another digest")
	}
}

func TestForgeZeroTrapdoorRejected(t *testing.T) {
	hk, _ := keyPair(t)
	digest, rs := hashOf(t, hk, []byte("a"))
	var tk Trapdoor
	if _, err := Forge(tk, []byte("a"), rs, []byte("b"), digest); err == nil {
		t.Fatal("Forge accepted an empty trapdoor")
	}
}

// A trapdoor loaded from bytes forges just like a fresh one.
func TestForgeAfterReload(t *testing.T) {
	hk, tk := keyPair(t)
	reloaded, err := TrapdoorFromBytes(tk.Bytes())
	if err != nil {
		t.Fatalf("TrapdoorFromBytes: %v", err)
	}
	digest, rs := hashOf(t, hk, []byte("original"))
	rsPrime, err := Forge(reloaded, []byte("original"), rs, []byte("redacted"), digest)
	if err != nil {
		t.Fatalf("Forge: %v", err)
	}
	if !Verify(hk, []byte("redacted"), rsPrime, digest) {
		t.Fatal("forge with the reloaded trapdoor did not collide")
	}
}

// The scalar field order is the one of BLS12-381.
func TestOrder(t *testing.T) {
	want, _ := new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
	if Order.Cmp(want) != 0 {
		t.Fatal("Order is not the BLS12-381 scalar field order")
	}
	if !Order.ProbablyPrime(32) {
		t.Fatal("Order is not prime")
	}
}
