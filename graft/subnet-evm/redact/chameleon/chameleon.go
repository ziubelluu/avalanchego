// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chameleon

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

var (
	// x can't be 0, otherwise 1/x in Forge doesn't exist.
	errZeroTrapdoor = errors.New("chameleon: trapdoor is zero")
	// r couldn't be read as a number.
	errBadRandomness = errors.New("chameleon: malformed randomness")
)

// DigestLen is the size of a digest: a compressed BLS12-381 G1 point, always 48 bytes.
const DigestLen = 48

// PublicKey is the public key y = g^x (a point on BLS12-381 G1).
type PublicKey struct {
	Y bls12381.G1Affine
}

// Trapdoor is the secret number x. Keep it local, never put it on chain.
type Trapdoor struct {
	X fr.Element
}

// hashToScalar turns a message into a number mod q: SHA-256(m) reduced mod q.
func hashToScalar(m []byte) fr.Element {
	sum := sha256.Sum256(m)
	var e fr.Element
	e.SetBytes(sum[:])
	return e
}

// scalarFromBytes reads r as a number mod q.
func scalarFromBytes(r []byte) fr.Element {
	var e fr.Element
	e.SetBytes(r)
	return e
}

// bigOf turns a scalar into a big.Int (what gnark wants for scalar mult).
func bigOf(e fr.Element) *big.Int {
	return e.BigInt(new(big.Int))
}

// KeyGen picks a random x and returns the public key y = g^x.
func KeyGen() (hk PublicKey, tk Trapdoor, err error) {
	if _, err = tk.X.SetRandom(); err != nil {
		return PublicKey{}, Trapdoor{}, err
	}
	hk.Y.ScalarMultiplicationBase(bigOf(tk.X))
	return hk, tk, nil
}

// digestPoint computes CH(m, r) = g^H(m) * y^r as a point.
func digestPoint(hk PublicKey, m, r []byte) bls12381.G1Affine {
	hm := hashToScalar(m)
	rr := scalarFromBytes(r)

	var gToHm, yToR, out bls12381.G1Affine
	gToHm.ScalarMultiplicationBase(bigOf(hm))
	yToR.ScalarMultiplication(&hk.Y, bigOf(rr))
	out.Add(&gToHm, &yToR)
	return out
}

// Hash returns the digest CH(m, r) = g^H(m) * y^r (48 bytes, compressed point).
func Hash(hk PublicKey, m, r []byte) (digest []byte) {
	d := digestPoint(hk, m, r)
	enc := d.Bytes()
	return enc[:]
}

// Verify checks that digest == CH(m, r).
func Verify(hk PublicKey, m, r, digest []byte) bool {
	return bytes.Equal(Hash(hk, m, r), digest)
}

// Forge uses x to find r' so that CH(m', r') == CH(m, r).
// The trick: r' = r + (H(m) - H(m')) / x  (mod q).
func Forge(tk Trapdoor, m, r, mPrime []byte) (rPrime []byte, err error) {
	if tk.X.IsZero() {
		return nil, errZeroTrapdoor
	}
	if len(r) == 0 {
		return nil, errBadRandomness
	}

	hm := hashToScalar(m)
	hmPrime := hashToScalar(mPrime)
	rr := scalarFromBytes(r)

	var diff, xInv, delta, out fr.Element
	diff.Sub(&hm, &hmPrime) // H(m) - H(m')
	xInv.Inverse(&tk.X)     // 1/x
	delta.Mul(&diff, &xInv) // (H(m) - H(m'))/x
	out.Add(&rr, &delta)    // r + (H(m) - H(m'))/x

	enc := out.Bytes()
	return enc[:], nil
}
