// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/ethdb"
)

var redactionProofPrefix = []byte("redaction-proof-")

var stateRedactionProofPrefix = []byte("state-redaction-proof-")

// proofKey = prefix + original block hash.
func proofKey(originalHash common.Hash) []byte {
	return append(append([]byte{}, redactionProofPrefix...), originalHash.Bytes()...)
}

// stateProofKey = prefix + proposal hash. State proofs are keyed by the proposal
// hash, not the block hash, because the committee approves the intent (not a
// specific post-forge body).
func stateProofKey(proposalHash common.Hash) []byte {
	return append(append([]byte{}, stateRedactionProofPrefix...), proposalHash.Bytes()...)
}

// WriteStateRedactionProof saves the proof for a state proposal.
func WriteStateRedactionProof(db ethdb.KeyValueWriter, proposalHash common.Hash, proof []byte) error {
	return db.Put(stateProofKey(proposalHash), proof)
}

// ReadStateRedactionProof reads back the proof for a state proposal.
func ReadStateRedactionProof(db ethdb.KeyValueReader, proposalHash common.Hash) ([]byte, error) {
	return db.Get(stateProofKey(proposalHash))
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

// DeleteRedactionProof removes the proof for the block.
func DeleteRedactionProof(db ethdb.KeyValueWriter, originalHash common.Hash) error {
	return db.Delete(proofKey(originalHash))
}
