// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chameleon

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestTrapdoorRoundTrip(t *testing.T) {
	hk, tk := keyPair(t)
	b := tk.Bytes()
	if len(b) != TrapdoorLen {
		t.Fatalf("trapdoor is %d bytes, want %d", len(b), TrapdoorLen)
	}
	back, err := TrapdoorFromBytes(b)
	if err != nil {
		t.Fatalf("TrapdoorFromBytes: %v", err)
	}
	if !bytes.Equal(back.Bytes(), b) {
		t.Fatal("trapdoor changed in the round trip")
	}
	// and it still belongs to the same public key
	if !bytes.Equal(back.PublicKey().Bytes(), hk.Bytes()) {
		t.Fatal("reloaded trapdoor gives another public key")
	}
}

func TestPublicKeyRoundTrip(t *testing.T) {
	hk, _ := keyPair(t)
	b := hk.Bytes()
	if len(b) != PublicKeyLen {
		t.Fatalf("public key is %d bytes, want %d", len(b), PublicKeyLen)
	}
	back, err := PublicKeyFromBytes(b)
	if err != nil {
		t.Fatalf("PublicKeyFromBytes: %v", err)
	}
	if !bytes.Equal(back.Bytes(), b) {
		t.Fatal("public key changed in the round trip")
	}
	digest, rs := hashOf(t, back, []byte("m"))
	if !Verify(hk, []byte("m"), rs, digest) {
		t.Fatal("the reloaded key is not the same key")
	}
}

func TestPublicKeyFromBytesRejectsGarbage(t *testing.T) {
	infinity := make([]byte, PublicKeyLen)
	infinity[0] = 0xc0
	notOnCurve := make([]byte, PublicKeyLen)
	notOnCurve[0] = 0x80
	notOnCurve[1] = 0xff
	for name, bad := range map[string][]byte{
		"nil":          nil,
		"short":        make([]byte, PublicKeyLen-1),
		"long":         make([]byte, PublicKeyLen+1),
		"zeros":        make([]byte, PublicKeyLen),
		"infinity":     infinity,
		"not on curve": notOnCurve,
	} {
		if _, err := PublicKeyFromBytes(bad); err == nil {
			t.Errorf("PublicKeyFromBytes accepted %s", name)
		}
	}
}

func TestLoadTrapdoorHex(t *testing.T) {
	_, tk := keyPair(t)
	h := hex.EncodeToString(tk.Bytes())
	for _, s := range []string{h, "0x" + h, "  " + h + "\n"} {
		got, err := LoadTrapdoorHex(s)
		if err != nil {
			t.Fatalf("LoadTrapdoorHex(%q): %v", s, err)
		}
		if !bytes.Equal(got.Bytes(), tk.Bytes()) {
			t.Fatal("loaded trapdoor differs")
		}
	}
}

func TestLoadTrapdoorRejectsZeroAndGarbage(t *testing.T) {
	zero := hex.EncodeToString(make([]byte, TrapdoorLen))
	q := hex.EncodeToString(Order.FillBytes(make([]byte, TrapdoorLen)))
	for name, s := range map[string]string{
		"empty":   "",
		"zero":    zero,
		"q":       q,
		"short":   "abcd",
		"not hex": "zz" + zero[2:],
	} {
		if _, err := LoadTrapdoorHex(s); err == nil {
			t.Errorf("LoadTrapdoorHex accepted %s", name)
		}
	}
}

func TestLoadTrapdoorEnv(t *testing.T) {
	const env = "CHAMELEON_TEST_TRAPDOOR"
	_, tk := keyPair(t)
	t.Setenv(env, "")
	if _, err := LoadTrapdoorEnv(env); err == nil {
		t.Fatal("LoadTrapdoorEnv accepted an empty variable")
	}
	t.Setenv(env, hex.EncodeToString(tk.Bytes()))
	got, err := LoadTrapdoorEnv(env)
	if err != nil {
		t.Fatalf("LoadTrapdoorEnv: %v", err)
	}
	if !bytes.Equal(got.Bytes(), tk.Bytes()) {
		t.Fatal("loaded trapdoor differs")
	}
}
