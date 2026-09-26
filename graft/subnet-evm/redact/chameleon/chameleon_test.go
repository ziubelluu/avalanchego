// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chameleon

import (
	"bytes"
	"math/big"
	"testing"
)

// freshRandomness returns a random r||s.
func freshRandomness(t *testing.T) []byte {
	t.Helper()
	rs, err := NewRandomness()
	if err != nil {
		t.Fatalf("NewRandomness: %v", err)
	}
	return rs
}

// TestGroupParameters checks the constants are right: p and q prime,
// p = 2q+1, g of order q. If I got a digit wrong in the hex this fails.
func TestGroupParameters(t *testing.T) {
	if P.BitLen() != 2048 {
		t.Fatalf("p has %d bits, want 2048", P.BitLen())
	}
	if !P.ProbablyPrime(32) {
		t.Fatal("p is not prime")
	}
	if !Q.ProbablyPrime(32) {
		t.Fatal("q is not prime")
	}
	twoQPlusOne := new(big.Int).Lsh(Q, 1)
	twoQPlusOne.Add(twoQPlusOne, big.NewInt(1))
	if twoQPlusOne.Cmp(P) != 0 {
		t.Fatal("p != 2q+1")
	}
	// g has order q: it's not 1 and g^q == 1
	if G.Cmp(big.NewInt(1)) == 0 {
		t.Fatal("g is 1")
	}
	if new(big.Int).Exp(G, Q, P).Cmp(big.NewInt(1)) != 0 {
		t.Fatal("g^q != 1 mod p, g is not in the order-q subgroup")
	}
	// and 2 is a quadratic residue because p = 7 mod 8
	if new(big.Int).Mod(P, big.NewInt(8)).Int64() != 7 {
		t.Fatal("p != 7 mod 8, 2 would not be a quadratic residue")
	}
}

func TestPublicKeyInSubgroup(t *testing.T) {
	hk, _, err := KeyGen()
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	if new(big.Int).Exp(hk.Y, Q, P).Cmp(big.NewInt(1)) != 0 {
		t.Fatal("y^q != 1, KeyGen produced a key outside QR_p")
	}
}

func TestHashVerifyRoundTrip(t *testing.T) {
	hk, _, err := KeyGen()
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	m := []byte("the original inert blob")
	r := freshRandomness(t)

	digest := Hash(hk, m, r)
	if len(digest) != DigestLen {
		t.Fatalf("digest len = %d, want %d", len(digest), DigestLen)
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
	if len(rPrime) != RandomnessLen {
		t.Fatalf("forged randomness len = %d, want %d", len(rPrime), RandomnessLen)
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

func TestForgeSameMessageStillVerifies(t *testing.T) {
	// Forging to the same message gives a different opening (k is new
	// every time), but it must still verify.
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

// TestForgeIsRandomized: forge the same thing twice, get two different
// openings. That's the random k.
func TestForgeIsRandomized(t *testing.T) {
	hk, tk, err := KeyGen()
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	m := []byte("original")
	mPrime := []byte("redacted")
	r := freshRandomness(t)
	digest := Hash(hk, m, r)

	rs1, err := Forge(tk, m, r, mPrime)
	if err != nil {
		t.Fatalf("Forge: %v", err)
	}
	rs2, err := Forge(tk, m, r, mPrime)
	if err != nil {
		t.Fatalf("Forge: %v", err)
	}
	if bytes.Equal(rs1, rs2) {
		t.Fatal("two forges gave the same randomness")
	}
	if !Verify(hk, mPrime, rs1, digest) || !Verify(hk, mPrime, rs2, digest) {
		t.Fatal("one of the two forged openings does not verify")
	}
}

// TestNoKeyExposure: a redaction publishes two openings of the same digest
// (the calldata before and after). Try to get x out of them with
// x = (H(m) - H(m')) / (b' - b), on r and on s: it doesn't come out, and
// g^result is not y.
func TestNoKeyExposure(t *testing.T) {
	hk, tk, err := KeyGen()
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	m := []byte("original blob")
	mPrime := []byte("")
	rs := freshRandomness(t)
	digest := Hash(hk, m, rs)

	rsPrime, err := Forge(tk, m, rs, mPrime)
	if err != nil {
		t.Fatalf("Forge: %v", err)
	}
	if !Verify(hk, mPrime, rsPrime, digest) {
		t.Fatal("forge did not collide")
	}

	r, s, _ := splitRandomness(rs)
	rPrime, sPrime, _ := splitRandomness(rsPrime)
	hm := hashToScalar(m, r)
	hmPrime := hashToScalar(mPrime, rPrime)

	// try x = (H(m) - H(m')) / (b' - b) with b = r and then b = s
	extract := func(b, bPrime *big.Int) *big.Int {
		num := new(big.Int).Sub(hm, hmPrime)
		den := new(big.Int).Sub(bPrime, b)
		den.Mod(den, Q)
		if den.Sign() == 0 {
			return nil
		}
		den.ModInverse(den, Q)
		return num.Mul(num, den).Mod(num, Q)
	}
	for name, cand := range map[string]*big.Int{
		"r": extract(r, rPrime),
		"s": extract(s, sPrime),
	} {
		if cand == nil {
			continue
		}
		if cand.Cmp(tk.X) == 0 {
			t.Fatalf("Krawczyk-Rabin extraction over %s recovered the trapdoor", name)
		}
		if new(big.Int).Exp(G, cand, P).Cmp(hk.Y) == 0 {
			t.Fatalf("extraction over %s gave a discrete log of y", name)
		}
	}

	// and forging again from the forged opening still works
	rsSecond, err := Forge(tk, mPrime, rsPrime, []byte("something else"))
	if err != nil {
		t.Fatalf("second Forge: %v", err)
	}
	if !Verify(hk, []byte("something else"), rsSecond, digest) {
		t.Fatal("chained forge did not collide")
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

	// flip the last byte of r and of s (the first byte could make it >= q,
	// which is a different error)
	for _, i := range []int{ElementLen - 1, RandomnessLen - 1} {
		rTampered := bytes.Clone(r)
		rTampered[i] ^= 0xFF
		if Verify(hk, m, rTampered, digest) {
			t.Fatalf("Verify accepted randomness tampered at byte %d", i)
		}
	}

	dTampered := bytes.Clone(digest)
	dTampered[len(dTampered)-1] ^= 0x01
	if Verify(hk, m, r, dTampered) {
		t.Fatal("Verify accepted a tampered digest")
	}
}

func TestMalformedRandomness(t *testing.T) {
	hk, tk, err := KeyGen()
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	m := []byte("blob")

	// r = q is not allowed
	tooBig := append(pad(Q), pad(big.NewInt(1))...)
	for _, bad := range [][]byte{nil, make([]byte, 32), make([]byte, RandomnessLen-1), tooBig} {
		if Hash(hk, m, bad) != nil {
			t.Fatalf("Hash accepted randomness of len %d", len(bad))
		}
		if Verify(hk, m, bad, make([]byte, DigestLen)) {
			t.Fatal("Verify accepted malformed randomness")
		}
		if _, err := Forge(tk, m, bad, m); err == nil {
			t.Fatal("Forge accepted malformed randomness")
		}
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
	var tk Trapdoor // X is nil
	if _, err := Forge(tk, []byte("a"), freshRandomness(t), []byte("b")); err == nil {
		t.Fatal("Forge accepted a zero trapdoor")
	}
	tk.X = new(big.Int)
	if _, err := Forge(tk, []byte("a"), freshRandomness(t), []byte("b")); err == nil {
		t.Fatal("Forge accepted x = 0")
	}
}

// A trapdoor loaded from bytes forges just like a fresh one.
func TestForgeAfterReload(t *testing.T) {
	hk, tk, err := KeyGen()
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	reloaded, err := TrapdoorFromBytes(tk.Bytes())
	if err != nil {
		t.Fatalf("TrapdoorFromBytes: %v", err)
	}
	m := []byte("original")
	r := freshRandomness(t)
	digest := Hash(hk, m, r)

	rPrime, err := Forge(reloaded, m, r, []byte("redacted"))
	if err != nil {
		t.Fatalf("Forge: %v", err)
	}
	if !Verify(hk, []byte("redacted"), rPrime, digest) {
		t.Fatal("forge with reloaded trapdoor did not collide")
	}
}
