// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package chameleon is the fully collision-resistant chameleon hash of Derler,
// Samelin and Slamanig ("Bringing Order to Chaos: The Case of
// Collision-Resistant Chameleon-Hashes", Construction 10), on G1 of BLS12-381.
//
// The digest is an ElGamal encryption of the message under the public key y:
// h = (c1, c2) = (g^rho, m * y^rho). The "randomness" r is a non-interactive
// OR-proof that either you know rho (you computed the hash honestly) or you
// know x, the trapdoor. Whoever hashes proves the first branch and fakes the
// second; whoever holds x does the opposite, and that's how a collision is
// made without touching the digest.
//
// The blob is turned into a group element with hash-to-curve first, and the
// statement (y, h, m) goes into the challenge, as the paper asks.
package chameleon

import (
	"crypto/rand"
	"errors"
	"math/big"

	blst "github.com/supranational/blst/bindings/go"
)

var (
	errNoTrapdoor    = errors.New("chameleon: trapdoor is not set")
	errNoPublicKey   = errors.New("chameleon: public key is not set")
	errBadRandomness = errors.New("chameleon: malformed randomness")
	errBadDigest     = errors.New("chameleon: malformed digest")
	errBadOpening    = errors.New("chameleon: the opening does not verify")
	errChallenge     = errors.New("chameleon: challenge hashed to zero")
)

// PublicKey is y = g^x.
type PublicKey struct {
	y *blst.P1
}

// Trapdoor is the secret x. Keep it local, never put it on chain.
// y is kept too so Forge doesn't recompute it every time.
type Trapdoor struct {
	x *big.Int
	y *blst.P1
}

// PublicKey gives back y.
func (tk Trapdoor) PublicKey() PublicKey {
	return PublicKey{y: tk.y}
}

// randScalar picks a random number in [1, q-1]. Zero is left out: as an
// ElGamal randomness it would make c1 the point at infinity, which nobody
// accepts.
func randScalar() (*big.Int, error) {
	k, err := rand.Int(rand.Reader, new(big.Int).Sub(Order, big.NewInt(1)))
	if err != nil {
		return nil, err
	}
	return k.Add(k, big.NewInt(1)), nil
}

// mul is p^k. k is reduced mod q first; k = 0 gives the identity.
func mul(p *blst.P1, k *big.Int) *blst.P1 {
	k = new(big.Int).Mod(k, Order)
	if k.Sign() == 0 {
		return new(blst.P1) // the zero value is the point at infinity
	}
	var s blst.Scalar
	if s.Deserialize(padScalar(k)) == nil {
		panic("chameleon: reduced scalar refused by blst")
	}
	return p.Mult(&s)
}

// mulNeg is p^(-k).
func mulNeg(p *blst.P1, k *big.Int) *blst.P1 {
	return mul(p, new(big.Int).Neg(k))
}

// toPoint maps the blob into G1.
func toPoint(m []byte) *blst.P1 {
	return blst.HashToG1(m, dstMessage)
}

// decodePoint reads a compressed point and makes sure it's a real element of
// G1: on the curve, in the right subgroup, and not the point at infinity.
func decodePoint(b []byte) (*blst.P1, bool) {
	if len(b) != PointLen || b[0]&0x40 != 0 {
		return nil, false
	}
	var a blst.P1Affine
	if a.Uncompress(b) == nil || !a.InG1() {
		return nil, false
	}
	var p blst.P1
	p.FromAffine(&a)
	return &p, true
}

// decodeScalar reads a big-endian number and refuses anything >= q.
func decodeScalar(b []byte) (*big.Int, bool) {
	v := new(big.Int).SetBytes(b)
	return v, v.Cmp(Order) < 0
}

// splitDigest reads (c1, c2).
func splitDigest(digest []byte) (c1, c2 *blst.P1, ok bool) {
	if len(digest) != DigestLen {
		return nil, nil, false
	}
	if c1, ok = decodePoint(digest[:PointLen]); !ok {
		return nil, nil, false
	}
	if c2, ok = decodePoint(digest[PointLen:]); !ok {
		return nil, nil, false
	}
	return c1, c2, true
}

// splitRandomness reads (e1, e2, s1, s2).
func splitRandomness(rs []byte) (e1, e2, s1, s2 *big.Int, ok bool) {
	if len(rs) != RandomnessLen {
		return nil, nil, nil, nil, false
	}
	parts := make([]*big.Int, 4)
	for i := range parts {
		if parts[i], ok = decodeScalar(rs[i*ScalarLen : (i+1)*ScalarLen]); !ok {
			return nil, nil, nil, nil, false
		}
	}
	return parts[0], parts[1], parts[2], parts[3], true
}

func joinRandomness(e1, e2, s1, s2 *big.Int) []byte {
	out := make([]byte, 0, RandomnessLen)
	for _, v := range []*big.Int{e1, e2, s1, s2} {
		out = append(out, padScalar(new(big.Int).Mod(v, Order))...)
	}
	return out
}

// challenge is the Fiat-Shamir hash e = H((y, h, m), (u11, u12, u2)), all
// points compressed, hashed into Z_q with hash-to-field.
func challenge(y, c1, c2, m, u11, u12, u2 *blst.P1) (*big.Int, error) {
	msg := make([]byte, 0, 7*PointLen)
	for _, p := range []*blst.P1{y, c1, c2, m, u11, u12, u2} {
		msg = append(msg, p.Compress()...)
	}
	s := blst.HashToScalar(msg, dstChallenge)
	if s == nil {
		return nil, errChallenge
	}
	return new(big.Int).SetBytes(s.ToBEndian()), nil
}

// KeyGen picks a random x in [1, q-1] and returns y = g^x with it.
func KeyGen() (hk PublicKey, tk Trapdoor, err error) {
	x, err := randScalar()
	if err != nil {
		return PublicKey{}, Trapdoor{}, err
	}
	y := mul(g, x)
	return PublicKey{y: y}, Trapdoor{x: x, y: y}, nil
}

// Hash encrypts m under y and proves it knows rho. It returns the digest
// (c1, c2) and the randomness (e1, e2, s1, s2); the second branch of the OR
// is simulated with a random (e2, s2).
func Hash(hk PublicKey, m []byte) (digest, rs []byte, err error) {
	if hk.y == nil {
		return nil, nil, errNoPublicKey
	}
	mp := toPoint(m)

	var rho, k1, e2, s2 *big.Int
	for _, p := range []**big.Int{&rho, &k1, &e2, &s2} {
		if *p, err = randScalar(); err != nil {
			return nil, nil, err
		}
	}

	c1 := mul(g, rho)
	c2 := mp.Add(mul(hk.y, rho))

	u11 := mul(g, k1)
	u12 := mul(hk.y, k1)
	u2 := mul(g, s2).Add(mulNeg(hk.y, e2))

	e, err := challenge(hk.y, c1, c2, mp, u11, u12, u2)
	if err != nil {
		return nil, nil, err
	}
	e1 := new(big.Int).Sub(e, e2)
	s1 := new(big.Int).Mul(e1, rho)
	s1.Add(s1, k1)

	digest = append(c1.Compress(), c2.Compress()...)
	return digest, joinRandomness(e1, e2, s1, s2), nil
}

// Verify checks the OR-proof rs for the statement (y, digest, m).
// No secret needed, and nothing is kept between calls.
func Verify(hk PublicKey, m, rs, digest []byte) bool {
	if hk.y == nil {
		return false
	}
	c1, c2, ok := splitDigest(digest)
	if !ok {
		return false
	}
	e1, e2, s1, s2, ok := splitRandomness(rs)
	if !ok {
		return false
	}
	mp := toPoint(m)

	u11 := mul(g, s1).Add(mulNeg(c1, e1))
	u12 := mul(hk.y, s1).Add(mulNeg(c2.Sub(mp), e1))
	u2 := mul(g, s2).Add(mulNeg(hk.y, e2))

	e, err := challenge(hk.y, c1, c2, mp, u11, u12, u2)
	if err != nil {
		return false
	}
	sum := new(big.Int).Add(e1, e2)
	sum.Mod(sum, Order)
	return sum.Cmp(e) == 0
}

// Forge uses x to open the same digest with mPrime: it first checks that
// (m, rs) really opens digest, then proves the trapdoor branch and simulates
// the other one. The result is random every time.
func Forge(tk Trapdoor, m, rs, mPrime, digest []byte) (rsPrime []byte, err error) {
	if tk.x == nil || tk.y == nil {
		return nil, errNoTrapdoor
	}
	if !Verify(PublicKey{y: tk.y}, m, rs, digest) {
		if _, _, ok := splitDigest(digest); !ok {
			return nil, errBadDigest
		}
		if _, _, _, _, ok := splitRandomness(rs); !ok {
			return nil, errBadRandomness
		}
		return nil, errBadOpening
	}
	c1, c2, _ := splitDigest(digest)
	mp := toPoint(mPrime)

	var k2, e1, s1 *big.Int
	for _, p := range []**big.Int{&k2, &e1, &s1} {
		if *p, err = randScalar(); err != nil {
			return nil, err
		}
	}

	u11 := mul(g, s1).Add(mulNeg(c1, e1))
	u12 := mul(tk.y, s1).Add(mulNeg(c2.Sub(mp), e1))
	u2 := mul(g, k2)

	e, err := challenge(tk.y, c1, c2, mp, u11, u12, u2)
	if err != nil {
		return nil, err
	}
	e2 := new(big.Int).Sub(e, e1)
	s2 := new(big.Int).Mul(e2, tk.x)
	s2.Add(s2, k2)

	return joinRandomness(e1, e2, s1, s2), nil
}
