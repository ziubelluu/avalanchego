// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chameleon

import (
	"encoding/hex"
	"testing"
)

func TestTrapdoorRoundTrip(t *testing.T) {
	_, tk, err := KeyGen()
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	b := tk.Bytes()
	if len(b) != 32 {
		t.Fatalf("trapdoor bytes len = %d, want 32", len(b))
	}
	got, err := TrapdoorFromBytes(b)
	if err != nil {
		t.Fatalf("TrapdoorFromBytes: %v", err)
	}
	if !got.X.Equal(&tk.X) {
		t.Fatal("trapdoor did not survive a Bytes -> FromBytes round trip")
	}
}

func TestPublicKeyRoundTrip(t *testing.T) {
	hk, _, err := KeyGen()
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	b := hk.Bytes()
	if len(b) != 48 {
		t.Fatalf("public key bytes len = %d, want 48", len(b))
	}
	got, err := PublicKeyFromBytes(b)
	if err != nil {
		t.Fatalf("PublicKeyFromBytes: %v", err)
	}
	if !got.Y.Equal(&hk.Y) {
		t.Fatal("public key did not survive a round trip")
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
		if !got.X.Equal(&tk.X) {
			t.Fatalf("LoadTrapdoorHex(%q) mismatch", s)
		}
	}
}

func TestLoadTrapdoorRejectsZeroAndGarbage(t *testing.T) {
	zero := make([]byte, 32)
	if _, err := TrapdoorFromBytes(zero); err == nil {
		t.Fatal("TrapdoorFromBytes accepted the zero scalar")
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
	if !got.X.Equal(&tk.X) {
		t.Fatal("LoadTrapdoorEnv mismatch")
	}
}
