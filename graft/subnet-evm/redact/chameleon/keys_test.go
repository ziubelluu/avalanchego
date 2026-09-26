// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chameleon

import (
	"encoding/hex"
	"math/big"
	"testing"
)

func TestTrapdoorRoundTrip(t *testing.T) {
	_, tk, err := KeyGen()
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	b := tk.Bytes()
	if len(b) != TrapdoorLen {
		t.Fatalf("trapdoor bytes len = %d, want %d", len(b), TrapdoorLen)
	}
	got, err := TrapdoorFromBytes(b)
	if err != nil {
		t.Fatalf("TrapdoorFromBytes: %v", err)
	}
	if got.X.Cmp(tk.X) != 0 {
		t.Fatal("trapdoor did not survive a Bytes -> FromBytes round trip")
	}
	if got.y.Cmp(tk.y) != 0 {
		t.Fatal("reloaded trapdoor derived a different y")
	}
}

func TestPublicKeyRoundTrip(t *testing.T) {
	hk, _, err := KeyGen()
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	b := hk.Bytes()
	if len(b) != PublicKeyLen {
		t.Fatalf("public key bytes len = %d, want %d", len(b), PublicKeyLen)
	}
	got, err := PublicKeyFromBytes(b)
	if err != nil {
		t.Fatalf("PublicKeyFromBytes: %v", err)
	}
	if got.Y.Cmp(hk.Y) != 0 {
		t.Fatal("public key did not survive a round trip")
	}
}

func TestPublicKeyFromBytesRejectsGarbage(t *testing.T) {
	bad := [][]byte{
		nil,
		make([]byte, 48),           // wrong size
		make([]byte, PublicKeyLen), // y = 0
		pad(big.NewInt(1)),         // y = 1
		pad(P),                     // y = p
		pad(new(big.Int).Add(P, big.NewInt(5))),
	}
	for _, b := range bad {
		if _, err := PublicKeyFromBytes(b); err == nil {
			t.Fatalf("PublicKeyFromBytes accepted %d bytes = %x...", len(b), b[:min(4, len(b))])
		}
	}
}

func TestLoadTrapdoorHex(t *testing.T) {
	_, tk, err := KeyGen()
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	h := hex.EncodeToString(tk.Bytes())

	for _, s := range []string{h, "0x" + h, "  " + h + "\n"} {
		got, err := LoadTrapdoorHex(s)
		if err != nil {
			t.Fatalf("LoadTrapdoorHex(%q): %v", s, err)
		}
		if got.X.Cmp(tk.X) != 0 {
			t.Fatalf("LoadTrapdoorHex(%q) mismatch", s)
		}
	}
}

func TestLoadTrapdoorRejectsZeroAndGarbage(t *testing.T) {
	if _, err := TrapdoorFromBytes(make([]byte, TrapdoorLen)); err == nil {
		t.Fatal("TrapdoorFromBytes accepted the zero scalar")
	}
	if _, err := TrapdoorFromBytes(make([]byte, 32)); err == nil {
		t.Fatal("TrapdoorFromBytes accepted a 32-byte (old size) scalar")
	}
	if _, err := TrapdoorFromBytes(pad(Q)); err == nil {
		t.Fatal("TrapdoorFromBytes accepted x = q")
	}
	if _, err := LoadTrapdoorHex("not-hex"); err == nil {
		t.Fatal("LoadTrapdoorHex accepted non-hex input")
	}
	if _, err := LoadTrapdoorHex(""); err == nil {
		t.Fatal("LoadTrapdoorHex accepted an empty secret")
	}
}

func TestLoadTrapdoorEnv(t *testing.T) {
	const envVar = "REDACT_TRAPDOOR_TEST"
	_, tk, err := KeyGen()
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}

	if _, err := LoadTrapdoorEnv(envVar); err == nil {
		t.Fatal("LoadTrapdoorEnv accepted an unset variable")
	}

	t.Setenv(envVar, hex.EncodeToString(tk.Bytes()))
	got, err := LoadTrapdoorEnv(envVar)
	if err != nil {
		t.Fatalf("LoadTrapdoorEnv: %v", err)
	}
	if got.X.Cmp(tk.X) != 0 {
		t.Fatal("LoadTrapdoorEnv mismatch")
	}
}
