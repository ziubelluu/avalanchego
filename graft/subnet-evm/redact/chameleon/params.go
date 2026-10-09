// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chameleon

import (
	"math/big"

	blst "github.com/supranational/blst/bindings/go"
)

// The group is G1 of BLS12-381, the same curve the validators use for their
// BLS signatures, so blst is already around. g is its standard generator and
// q the prime order of the group (the scalar field).
var (
	// Order is q, the order of G1.
	Order, _ = new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
	g        = blst.P1Generator()
)

// Domain separation tags: one to turn the blob into a group element, a
// different one for the Fiat-Shamir challenge.
var (
	dstMessage   = []byte("SUBNET-EVM-REDACT-CH-MSG-V1")
	dstChallenge = []byte("SUBNET-EVM-REDACT-CH-CHAL-V1")
)

const (
	// PointLen is a compressed G1 point.
	PointLen = 48
	// ScalarLen is a number mod q, big-endian.
	ScalarLen = 32

	// PublicKeyLen is y = g^x, one point.
	PublicKeyLen = PointLen
	// TrapdoorLen is x, one scalar.
	TrapdoorLen = ScalarLen
	// DigestLen is the ElGamal ciphertext (c1, c2), two points.
	DigestLen = 2 * PointLen
	// RandomnessLen is the proof (e1, e2, s1, s2), four scalars.
	RandomnessLen = 4 * ScalarLen
)

// padScalar writes v (already reduced mod q) into exactly ScalarLen bytes.
func padScalar(v *big.Int) []byte {
	return v.FillBytes(make([]byte, ScalarLen))
}
