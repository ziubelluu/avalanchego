// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/ethdb"
)

var redactionProofPrefix = []byte("redaction-proof-")

// proofKey = prefix + original block hash.
func proofKey(originalHash common.Hash) []byte {
	return append(append([]byte{}, redactionProofPrefix...), originalHash.Bytes()...)
}

// WriteRedactionProof stores the proof bytes for the block OriginalHash.
func WriteRedactionProof(db ethdb.KeyValueWriter, originalHash common.Hash, proof []byte) error {
	return db.Put(proofKey(originalHash), proof)
}

// ReadRedactionProof returns the proof bytes, or an error if none is stored.
func ReadRedactionProof(db ethdb.KeyValueReader, originalHash common.Hash) ([]byte, error) {
	return db.Get(proofKey(originalHash))
}

// HasRedactionProof reports whether a proof is stored for the block.
func HasRedactionProof(db ethdb.KeyValueReader, originalHash common.Hash) (bool, error) {
	return db.Has(proofKey(originalHash))
}
