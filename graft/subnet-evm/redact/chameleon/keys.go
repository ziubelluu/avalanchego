// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chameleon

import (
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"strings"
)

var (
	errBadTrapdoor  = errors.New("chameleon: malformed trapdoor")
	errTrapdoorZero = errors.New("chameleon: trapdoor must be in [1, q-1]")
	errBadPublicKey = errors.New("chameleon: malformed public key")
	errNoSecret     = errors.New("chameleon: trapdoor secret not set")
)

// Bytes turns the trapdoor x into TrapdoorLen bytes (y is not saved).
func (tk Trapdoor) Bytes() []byte {
	if tk.x == nil {
		return make([]byte, TrapdoorLen)
	}
	return padScalar(tk.x)
}

// TrapdoorFromBytes reads x from TrapdoorLen bytes (refusing 0 and anything
// >= q), then computes y.
func TrapdoorFromBytes(b []byte) (Trapdoor, error) {
	if len(b) != TrapdoorLen {
		return Trapdoor{}, errBadTrapdoor
	}
	x := new(big.Int).SetBytes(b)
	if x.Sign() == 0 || x.Cmp(Order) >= 0 {
		return Trapdoor{}, errTrapdoorZero
	}
	return Trapdoor{x: x, y: mul(g, x)}, nil
}

// Bytes turns the public key into PublicKeyLen bytes (compressed point).
func (hk PublicKey) Bytes() []byte {
	if hk.y == nil {
		return make([]byte, PublicKeyLen)
	}
	return hk.y.Compress()
}

// PublicKeyFromBytes reads y. It must be a point of G1 other than infinity.
func PublicKeyFromBytes(b []byte) (PublicKey, error) {
	y, ok := decodePoint(b)
	if !ok {
		return PublicKey{}, errBadPublicKey
	}
	return PublicKey{y: y}, nil
}

// LoadTrapdoorHex reads the trapdoor from a hex string (0x prefix optional).
// The string comes from a local secret (config file, env var).
func LoadTrapdoorHex(s string) (Trapdoor, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	if s == "" {
		return Trapdoor{}, errNoSecret
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return Trapdoor{}, errBadTrapdoor
	}
	return TrapdoorFromBytes(raw)
}

// LoadTrapdoorEnv reads the trapdoor from an env var. If it's not set, it
// fails: a node without the secret just can't forge.
func LoadTrapdoorEnv(envVar string) (Trapdoor, error) {
	v, ok := os.LookupEnv(envVar)
	if !ok || strings.TrimSpace(v) == "" {
		return Trapdoor{}, errNoSecret
	}
	return LoadTrapdoorHex(v)
}
