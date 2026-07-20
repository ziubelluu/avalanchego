// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chameleon

import (
	"encoding/hex"
	"errors"
	"os"
	"strings"
)

var (
	errBadTrapdoor      = errors.New("chameleon: malformed trapdoor")
	errZeroTrapdoorLoad = errors.New("chameleon: trapdoor must be non-zero")
	errBadPublicKey     = errors.New("chameleon: malformed public key")
	errNoSecret         = errors.New("chameleon: trapdoor secret not set")
)

// Bytes turns the trapdoor x into 32 bytes.
func (tk Trapdoor) Bytes() []byte {
	b := tk.X.Bytes()
	return b[:]
}

// TrapdoorFromBytes reads a trapdoor from 32 bytes (and refuses 0).
func TrapdoorFromBytes(b []byte) (Trapdoor, error) {
	var tk Trapdoor
	if err := tk.X.SetBytesCanonical(b); err != nil {
		return Trapdoor{}, errBadTrapdoor
	}
	if tk.X.IsZero() {
		return Trapdoor{}, errZeroTrapdoorLoad
	}
	return tk, nil
}

// Bytes turns the public key into 48 bytes (compressed point).
func (hk PublicKey) Bytes() []byte {
	b := hk.Y.Bytes()
	return b[:]
}

// PublicKeyFromBytes reads a public key from 48 bytes.
func PublicKeyFromBytes(b []byte) (PublicKey, error) {
	var hk PublicKey
	if _, err := hk.Y.SetBytes(b); err != nil {
		return PublicKey{}, errBadPublicKey
	}
	return hk, nil
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
