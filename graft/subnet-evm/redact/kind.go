// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import "errors"

// Kind says what kind of proof some stored bytes are. It's the first byte of
// the encoding, so a tx proof can't be read as a deposit proof by mistake.
type Kind byte

const (
	// KindTx is a Proof: some transactions of the block had their calldata removed.
	KindTx Kind = 0x01
	// KindState is a StateProof: a deposit in the block got a new opening.
	KindState Kind = 0x02
)

var (
	errEmptyProof  = errors.New("redact: empty proof")
	errUnknownKind = errors.New("redact: unknown proof kind")
	errWrongKind   = errors.New("redact: proof is of another kind")
)

// KindOf reads the kind byte of an encoded proof.
func KindOf(raw []byte) (Kind, error) {
	if len(raw) == 0 {
		return 0, errEmptyProof
	}
	switch k := Kind(raw[0]); k {
	case KindTx, KindState:
		return k, nil
	default:
		return 0, errUnknownKind
	}
}

// withKind puts the kind byte in front of the encoded proof.
func withKind(k Kind, body []byte) []byte {
	return append([]byte{byte(k)}, body...)
}

// stripKind checks the kind byte and returns what follows it.
func stripKind(want Kind, raw []byte) ([]byte, error) {
	k, err := KindOf(raw)
	if err != nil {
		return nil, err
	}
	if k != want {
		return nil, errWrongKind
	}
	return raw[1:], nil
}
