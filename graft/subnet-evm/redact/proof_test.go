// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redact

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/snow/validators"
	"github.com/ava-labs/avalanchego/utils/constants"
	"github.com/ava-labs/avalanchego/utils/crypto/bls"
	"github.com/ava-labs/avalanchego/utils/crypto/bls/signer/localsigner"
	"github.com/ava-labs/avalanchego/utils/set"
	"github.com/ava-labs/avalanchego/vms/platformvm/warp"
)

var proofSourceChainID = ids.GenerateTestID()

// makeCommitteeWeights builds one validator per given weight, in canonical
// order, plus a lookup from canonical index to its signer.
func makeCommitteeWeights(t testing.TB, weights ...uint64) (validators.WarpSet, map[int]bls.Signer) {
	t.Helper()

	byPK := map[string]bls.Signer{}
	vdrSet := map[ids.NodeID]*validators.GetValidatorOutput{}
	for _, w := range weights {
		sk, err := localsigner.New()
		require.NoError(t, err)
		nodeID := ids.GenerateTestNodeID()
		vdrSet[nodeID] = &validators.GetValidatorOutput{
			NodeID:    nodeID,
			PublicKey: sk.PublicKey(),
			Weight:    w,
		}
		byPK[string(bls.PublicKeyToUncompressedBytes(sk.PublicKey()))] = sk
	}

	ws, err := validators.FlattenValidatorSet(vdrSet)
	require.NoError(t, err)

	byIndex := map[int]bls.Signer{}
	for i, v := range ws.Validators {
		byIndex[i] = byPK[string(v.PublicKeyBytes)]
	}
	return ws, byIndex
}

// makeCommittee builds n validators with weight 1 each.
func makeCommittee(t testing.TB, n int) (validators.WarpSet, map[int]bls.Signer) {
	t.Helper()

	weights := make([]uint64, n)
	for i := range weights {
		weights[i] = 1
	}
	return makeCommitteeWeights(t, weights...)
}

// signProof signs the proposal with the given canonical indices and packs the
// aggregated signature into a Proof.
func signProof(t testing.TB, p *Proposal, byIndex map[int]bls.Signer, indices ...int) *Proof {
	t.Helper()

	msg, err := warp.NewUnsignedMessage(constants.UnitTestID, proofSourceChainID, p.Bytes())
	require.NoError(t, err)
	msgBytes := msg.Bytes()

	signers := set.NewBits()
	sigs := make([]*bls.Signature, 0, len(indices))
	for _, idx := range indices {
		sig, err := byIndex[idx].Sign(msgBytes)
		require.NoError(t, err)
		sigs = append(sigs, sig)
		signers.Add(idx)
	}
	aggSig, err := bls.AggregateSignatures(sigs)
	require.NoError(t, err)

	proof := &Proof{Proposal: *p, SignerBitSet: signers.Bytes()}
	copy(proof.AggSignature[:], bls.SignatureToBytes(aggSig))
	return proof
}

// Full committee signs -> quorum reached.
func TestVerifyRedactionProofQuorumReached(t *testing.T) {
	t.Parallel()

	ws, byIndex := makeCommittee(t, 3)
	proof := signProof(t, sampleProposal(), byIndex, 0, 1, 2)

	require.NoError(t, VerifyRedactionProof(proof, constants.UnitTestID, proofSourceChainID, ws, 2, 3))
}

// Only one of three signs -> below the 2/3 quorum -> rejected.
func TestVerifyRedactionProofBelowQuorum(t *testing.T) {
	t.Parallel()

	ws, byIndex := makeCommittee(t, 3)
	proof := signProof(t, sampleProposal(), byIndex, 0)

	require.Error(t, VerifyRedactionProof(proof, constants.UnitTestID, proofSourceChainID, ws, 2, 3))
}

// Weights matter, not head count: with weights 1/1/100 and a 2/3 quorum over a
// total of 102, the two light validators together (weight 2) are not enough,
// but the single heavy validator (weight 100) is.
func TestVerifyRedactionProofWeighted(t *testing.T) {
	t.Parallel()

	ws, byIndex := makeCommitteeWeights(t, 1, 1, 100)

	var heavy int
	var light []int
	for i, v := range ws.Validators {
		if v.Weight == 100 {
			heavy = i
		} else {
			light = append(light, i)
		}
	}

	// The two light validators sign, the heavy one abstains -> rejected.
	lightProof := signProof(t, sampleProposal(), byIndex, light...)
	require.Error(t, VerifyRedactionProof(lightProof, constants.UnitTestID, proofSourceChainID, ws, 2, 3))

	// The heavy validator alone signs -> accepted.
	heavyProof := signProof(t, sampleProposal(), byIndex, heavy)
	require.NoError(t, VerifyRedactionProof(heavyProof, constants.UnitTestID, proofSourceChainID, ws, 2, 3))
}

// Malformed (not strictly increasing) redacted indices are rejected.
func TestVerifyRedactionProofMalformedIndices(t *testing.T) {
	t.Parallel()

	ws, byIndex := makeCommittee(t, 3)
	proof := signProof(t, sampleProposal(), byIndex, 0, 1, 2)
	proof.Proposal.RedactedIndices = []uint64{1, 1} // duplicate -> not strictly increasing

	require.ErrorIs(t, VerifyRedactionProof(proof, constants.UnitTestID, proofSourceChainID, ws, 2, 3), errMalformedRedactedIndices)
}

// A proof for one proposal must not verify against a different proposal.
func TestVerifyRedactionProofWrongProposal(t *testing.T) {
	t.Parallel()

	ws, byIndex := makeCommittee(t, 3)
	proof := signProof(t, sampleProposal(), byIndex, 0, 1, 2)
	proof.Proposal.NewTxHash[0] ^= 0xff // tamper after signing

	require.Error(t, VerifyRedactionProof(proof, constants.UnitTestID, proofSourceChainID, ws, 2, 3))
}

// Proof round-trips through Bytes/ProofFromBytes.
func TestProofRoundTrip(t *testing.T) {
	t.Parallel()

	_, byIndex := makeCommittee(t, 3)
	want := signProof(t, sampleProposal(), byIndex, 0, 1, 2)

	b, err := want.Bytes()
	require.NoError(t, err)
	got, err := ProofFromBytes(b)
	require.NoError(t, err)
	require.Equal(t, want, got)
}
