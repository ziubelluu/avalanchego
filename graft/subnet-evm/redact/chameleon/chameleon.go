// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package chameleon is the chameleon hash from the Ateniese et al. paper
// (section 3.4.2): h = r - (y^H(m||r) * g^s mod p) mod q, with trapdoor x
// and public key y = g^x.
//
// Forge picks a fresh random k every time, so seeing the openings of a
// redaction (the calldata before and after) doesn't give x away.
package chameleon

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
)

var (
	// x can't be 0 (y would be 1), and an empty Trapdoor has no x at all.
	errZeroTrapdoor = errors.New("chameleon: trapdoor is zero")
	// r||s has the wrong length or r or s is >= q.
	errBadRandomness = errors.New("chameleon: malformed randomness")
)

// PublicKey is y = g^x mod p.
type PublicKey struct {
	Y *big.Int
}

// Trapdoor is the secret x. Keep it local, never put it on chain.
// y is here too so Forge doesn't have to recompute it from x every time.
type Trapdoor struct {
	X *big.Int
	y *big.Int
}

// hashToScalar is H(m||r): SHA-256 of m followed by r (r is always 256
// bytes, so you know where m ends), read as a number. It's already < q.
func hashToScalar(m []byte, r *big.Int) *big.Int {
	h := sha256.New()
	h.Write(m)
	h.Write(pad(r))
	return new(big.Int).SetBytes(h.Sum(nil))
}

// randScalar picks a random number in [1, q-1].
func randScalar() (*big.Int, error) {
	k, err := rand.Int(rand.Reader, new(big.Int).Sub(Q, big.NewInt(1)))
	if err != nil {
		return nil, err
	}
	return k.Add(k, big.NewInt(1)), nil
}

// splitRandomness reads r and s out of r||s. Both must be < q.
func splitRandomness(rs []byte) (r, s *big.Int, ok bool) {
	if len(rs) != RandomnessLen {
		return nil, nil, false
	}
	r = new(big.Int).SetBytes(rs[:ElementLen])
	s = new(big.Int).SetBytes(rs[ElementLen:])
	if r.Cmp(Q) >= 0 || s.Cmp(Q) >= 0 {
		return nil, nil, false
	}
	return r, s, true
}

// joinRandomness puts r and s back together.
func joinRandomness(r, s *big.Int) []byte {
	return append(pad(r), pad(s)...)
}

// NewRandomness picks a fresh (r, s). This is what you use to hash a blob.
func NewRandomness() ([]byte, error) {
	r, err := randScalar()
	if err != nil {
		return nil, err
	}
	s, err := randScalar()
	if err != nil {
		return nil, err
	}
	return joinRandomness(r, s), nil
}

// KeyGen picks a random x and returns the public key y = g^x.
func KeyGen() (hk PublicKey, tk Trapdoor, err error) {
	x, err := randScalar()
	if err != nil {
		return PublicKey{}, Trapdoor{}, err
	}
	y := new(big.Int).Exp(G, x, P)
	return PublicKey{Y: y}, Trapdoor{X: x, y: y}, nil
}

// digestInt computes h = r - (y^H(m||r) * g^s mod p) mod q as a number.
func digestInt(y *big.Int, m []byte, r, s *big.Int) *big.Int {
	e := hashToScalar(m, r)
	t := new(big.Int).Exp(y, e, P)
	t.Mul(t, new(big.Int).Exp(G, s, P))
	t.Mod(t, P)
	h := new(big.Int).Sub(r, t)
	return h.Mod(h, Q)
}

// Hash returns the digest of m with randomness rs = r||s (DigestLen bytes).
// nil if rs is malformed or the key is empty (nil never verifies).
func Hash(hk PublicKey, m, rs []byte) (digest []byte) {
	r, s, ok := splitRandomness(rs)
	if !ok || hk.Y == nil {
		return nil
	}
	return pad(digestInt(hk.Y, m, r, s))
}

// Verify checks that digest == Hash(m, rs). No secret needed.
func Verify(hk PublicKey, m, rs, digest []byte) bool {
	d := Hash(hk, m, rs)
	return d != nil && bytes.Equal(d, digest)
}

// Forge uses x to find (r', s') so that Hash(m', r'||s') == Hash(m, r||s).
// k is random every time, so two forges of the same thing give different
// results and don't leak x.
func Forge(tk Trapdoor, m, rs, mPrime []byte) (rsPrime []byte, err error) {
	if tk.X == nil || tk.X.Sign() == 0 {
		return nil, errZeroTrapdoor
	}
	r, s, ok := splitRandomness(rs)
	if !ok {
		return nil, errBadRandomness
	}
	y := tk.y
	if y == nil {
		y = new(big.Int).Exp(G, tk.X, P)
	}
	h := digestInt(y, m, r, s)

	k, err := randScalar()
	if err != nil {
		return nil, err
	}
	// r' = h + (g^k mod p) mod q
	rPrime := new(big.Int).Exp(G, k, P)
	rPrime.Add(rPrime, h)
	rPrime.Mod(rPrime, Q)
	// s' = k - H(m'||r') * x mod q
	sPrime := hashToScalar(mPrime, rPrime)
	sPrime.Mul(sPrime, tk.X)
	sPrime.Sub(k, sPrime)
	sPrime.Mod(sPrime, Q)

	return joinRandomness(rPrime, sPrime), nil
}
