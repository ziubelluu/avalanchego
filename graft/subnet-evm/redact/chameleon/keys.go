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
	errBadTrapdoor      = errors.New("chameleon: malformed trapdoor")
	errZeroTrapdoorLoad = errors.New("chameleon: trapdoor must be in [1, q-1]")
	errBadPublicKey     = errors.New("chameleon: malformed public key")
	errNoSecret         = errors.New("chameleon: trapdoor secret not set")
)

// Bytes turns the trapdoor x into TrapdoorLen bytes (y is not saved).
func (tk Trapdoor) Bytes() []byte {
	if tk.X == nil {
		return make([]byte, TrapdoorLen)
	}
	return pad(tk.X)
}

// TrapdoorFromBytes reads x from TrapdoorLen bytes (and refuses 0 or
// anything >= q), then computes y.
func TrapdoorFromBytes(b []byte) (Trapdoor, error) {
	if len(b) != TrapdoorLen {
		return Trapdoor{}, errBadTrapdoor
	}
	x := new(big.Int).SetBytes(b)
	if x.Sign() == 0 || x.Cmp(Q) >= 0 {
		return Trapdoor{}, errZeroTrapdoorLoad
	}
	return Trapdoor{X: x, y: new(big.Int).Exp(G, x, P)}, nil
}

// Bytes turns the public key into PublicKeyLen bytes.
func (hk PublicKey) Bytes() []byte {
	if hk.Y == nil {
		return make([]byte, PublicKeyLen)
	}
	return pad(hk.Y)
}

// PublicKeyFromBytes reads y from PublicKeyLen bytes. It only checks
// 1 < y < p: checking the subgroup too would be one more exponentiation on
// every precompile call.
func PublicKeyFromBytes(b []byte) (PublicKey, error) {
	if len(b) != PublicKeyLen {
		return PublicKey{}, errBadPublicKey
	}
	y := new(big.Int).SetBytes(b)
	if y.Cmp(big.NewInt(1)) <= 0 || y.Cmp(P) >= 0 {
		return PublicKey{}, errBadPublicKey
	}
	return PublicKey{Y: y}, nil
}

// LoadTrapdoorHex reads the trapdoor from a hex string (0x prefix optional).
// The string comes from a local secret (config, keystore, env var).
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

// LoadTrapdoorEnv reads the trapdoor from an env var. If it's not set, it fails:
// a node without the secret just can't forge.
func LoadTrapdoorEnv(envVar string) (Trapdoor, error) {
	v, ok := os.LookupEnv(envVar)
	if !ok || strings.TrimSpace(v) == "" {
		return Trapdoor{}, errNoSecret
	}
	return LoadTrapdoorHex(v)
}
