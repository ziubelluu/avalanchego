// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package core

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core/rawdb"
	"github.com/ava-labs/libevm/core/types"
	"github.com/ava-labs/libevm/crypto"
	"github.com/ava-labs/libevm/ethdb"
	"github.com/stretchr/testify/require"

	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/snow/validators"
	"github.com/ava-labs/avalanchego/utils"
	"github.com/ava-labs/avalanchego/utils/constants"
	"github.com/ava-labs/avalanchego/utils/crypto/bls"
	"github.com/ava-labs/avalanchego/utils/crypto/bls/signer/localsigner"
	"github.com/ava-labs/avalanchego/utils/set"
	"github.com/ava-labs/avalanchego/vms/platformvm/warp"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/params"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/params/extras"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/precompile/contracts/chameleonhash"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact/redactabledeposit"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact/chameleon"
)

// buildCommittee creates n equally-weighted validators with BLS keys and a
// canonical-index -> signer lookup.
func buildCommittee(t *testing.T, n int) (validators.WarpSet, map[int]bls.Signer) {
	t.Helper()
	byPK := map[string]bls.Signer{}
	vdrSet := map[ids.NodeID]*validators.GetValidatorOutput{}
	for i := 0; i < n; i++ {
		sk, err := localsigner.New()
		require.NoError(t, err)
		nodeID := ids.GenerateTestNodeID()
		vdrSet[nodeID] = &validators.GetValidatorOutput{NodeID: nodeID, PublicKey: sk.PublicKey(), Weight: 1}
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

// signStateProof collects committee signatures over the state proposal and packs
// them into a StateProof (the on-chain record that the vote passed).
func signStateProof(t *testing.T, networkID uint32, sourceChainID ids.ID, sp *redact.StateProposal, byIndex map[int]bls.Signer, indices ...int) *redact.StateProof {
	t.Helper()
	msg, err := warp.NewUnsignedMessage(networkID, sourceChainID, sp.Bytes())
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

	proof := &redact.StateProof{Proposal: *sp, SignerBitSet: signers.Bytes()}
	copy(proof.AggSignature[:], bls.SignatureToBytes(aggSig))
	return proof
}

// depositChain is a running chain where block 0 deploys a RedactableDeposit
// contract and stores one (blob, r) deposit into it.
type depositChain struct {
	db          ethdb.Database
	gspec       *Genesis
	bc          *BlockChain
	block0      *types.Block
	block1      *types.Block
	depositAddr common.Address
	storeTx     *types.Transaction
	key         *ecdsa.PrivateKey
	signer      types.Signer
}

// storeNonceTx signs a tx to the deposit contract with the store nonce (1).
func (d *depositChain) redactedStoreTx(t *testing.T, calldata []byte) *types.Transaction {
	t.Helper()
	tx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{
		Nonce: 1, GasTipCap: big.NewInt(0), GasFeeCap: big.NewInt(225_000_000_000),
		Gas: d.storeTx.Gas(), To: &d.depositAddr, Data: calldata,
	}), d.signer, d.key)
	require.NoError(t, err)
	return tx
}

// newTxsWithRedactedStore returns block 0's tx list with the store tx replaced.
func (d *depositChain) newTxsWithRedactedStore(redacted *types.Transaction) []*types.Transaction {
	out := make([]*types.Transaction, len(d.block0.Transactions()))
	for i, tx := range d.block0.Transactions() {
		if tx.Hash() == d.storeTx.Hash() {
			out[i] = redacted
		} else {
			out[i] = tx
		}
	}
	return out
}

// setupDepositChain deploys the deposit contract and stores (blob, r, digest).
func setupDepositChain(t *testing.T, hkBytes []byte, id common.Hash, blob, r, digest []byte) *depositChain {
	t.Helper()
	require := require.New(t)

	chainCfg := params.Copy(params.TestChainConfig)
	chCfg := chameleonhash.NewConfig(utils.PointerTo[uint64](0))
	params.GetExtra(&chainCfg).GenesisPrecompiles = extras.Precompiles{chCfg.Key(): chCfg}

	key, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	addr := crypto.PubkeyToAddress(key.PublicKey)
	signer := types.LatestSigner(&chainCfg)
	db := rawdb.NewMemoryDatabase()
	gspec := &Genesis{
		Config:   &chainCfg,
		Alloc:    types.GenesisAlloc{addr: {Balance: big.NewInt(1_000_000_000_000_000_000)}},
		GasLimit: params.GetExtra(&chainCfg).FeeConfig.GasLimit.Uint64(),
	}

	deployCode, err := redactabledeposit.DeployCode(hkBytes)
	require.NoError(err)
	depositAddr := crypto.CreateAddress(addr, 0)
	storeCalldata, err := redactabledeposit.PackStore(id, blob, r, digest)
	require.NoError(err)

	mkTx := func(nonce uint64, to *common.Address, data []byte) *types.Transaction {
		tx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{
			Nonce: nonce, GasTipCap: big.NewInt(0), GasFeeCap: big.NewInt(225_000_000_000),
			Gas: 3_000_000, To: to, Data: data,
		}), signer, key)
		require.NoError(err)
		return tx
	}
	deployTx := mkTx(0, nil, deployCode)
	storeTx := mkTx(1, &depositAddr, storeCalldata)

	bc, err := createBlockChain(db, DefaultCacheConfig, gspec, common.Hash{})
	require.NoError(err)

	_, chain, _, err := GenerateChainWithGenesis(gspec, bc.engine, 2, 10, func(i int, gen *BlockGen) {
		if i == 0 {
			gen.AddTx(deployTx)
			gen.AddTx(storeTx)
		}
	})
	require.NoError(err)
	_, err = bc.InsertChain(chain)
	require.NoError(err)
	for _, blk := range chain {
		require.NoError(bc.Accept(blk))
	}
	bc.DrainAcceptorQueue()

	// Sanity: the deposit really committed the digest.
	st, err := bc.State()
	require.NoError(err)
	require.Equal(digest, redactabledeposit.GetDigest(st, depositAddr, id), "store must have committed the digest")

	return &depositChain{
		db: db, gspec: gspec, bc: bc,
		block0: chain[0], block1: chain[1],
		depositAddr: depositAddr, storeTx: storeTx, key: key, signer: signer,
	}
}

// TestChameleonHappyPathE2E: deposit (blob, r) into a deployed contract, the
// committee votes, we forge r' for an empty blob and swap the opening, then a
// re-spawned node checks CH("", r') == D with the roots unchanged.
func TestChameleonHappyPathE2E(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	hk, tk, err := chameleon.KeyGen()
	require.NoError(err)
	blob := bytes.Repeat([]byte{0xAB, 0xCD, 0xEF, 0x12}, 256)
	r := bytes.Repeat([]byte{0x07}, 32)
	digest := chameleon.Hash(hk, blob, r)
	id := crypto.Keccak256Hash([]byte("deposit-1"))

	dc := setupDepositChain(t, hk.Bytes(), id, blob, r, digest)
	depositAddr := dc.depositAddr

	require.True(dbContains(dc.db, blob), "blob should be stored before redaction")

	// Committee votes to authorize the redaction (intent: blob -> empty).
	networkID := constants.UnitTestID
	sourceChainID := ids.GenerateTestID()
	ws, byIndex := buildCommittee(t, 3)
	blobPrime := []byte{}
	sp := &redact.StateProposal{
		OriginalHash: dc.block0.Hash(),
		DepositAddr:  depositAddr,
		ID:           id,
		Digest:       digest,
		NewBlobHash:  crypto.Keccak256Hash(blobPrime),
		PChainHeight: 1,
	}
	proof := signStateProof(t, networkID, sourceChainID, sp, byIndex, 0, 1, 2)
	proofBytes, err := proof.Bytes()
	require.NoError(err)
	require.NoError(redact.WriteStateRedactionProof(dc.db, sp.Hash(), proofBytes))

	warpSet := func(context.Context, uint64) (validators.WarpSet, error) { return ws, nil }
	approver := redact.NewCommitteeStatePolicy(dc.db, warpSet, networkID, sourceChainID, 2, 3)

	// Vote-gated forge.
	forger := redact.NewForger(approver, tk)
	rPrime, err := forger.Forge(ctx, sp, blob, r, blobPrime)
	require.NoError(err)
	require.True(chameleon.Verify(hk, blobPrime, rPrime, digest), "CH(blob', r') must equal D")

	// Apply: rebuild the store calldata with (blob'="", r') and swap the body.
	redactedCalldata, err := redactabledeposit.RedactedStoreCalldata(dc.storeTx.Data(), blobPrime, rPrime)
	require.NoError(err)
	redactedTx := dc.redactedStoreTx(t, redactedCalldata)
	redacted := redact.RedactBlock(dc.block0, dc.newTxsWithRedactedStore(redactedTx))
	require.NoError(redact.Persist(dc.db, dc.block0.Hash(), redacted))

	dc.bc.Stop()

	// Re-spawn a node from cold storage with the consensus content check.
	bc2, err := createBlockChain(dc.db, DefaultCacheConfig, dc.gspec, dc.block1.Hash())
	require.NoError(err)
	defer bc2.Stop()
	bc2.SetRedactionContentVerifier(redactabledeposit.VerifyRedactedBlock)

	require.False(dbContains(dc.db, blob), "blob should be gone after redaction")

	got := rawdb.ReadBlock(dc.db, dc.block0.Hash(), dc.block0.NumberU64())
	require.NotNil(got)
	storeTxBack, ok := redactabledeposit.FindStoreTx(got, depositAddr, id)
	require.True(ok)
	gotID, gotBlob, gotR, gotDigest, err := redactabledeposit.UnpackStoreInput(storeTxBack.Data()[4:])
	require.NoError(err)
	require.Equal(id, gotID)
	require.Empty(gotBlob)
	require.Equal(rPrime, gotR)
	require.Equal(digest, gotDigest)

	// State roots of this and the following block are unchanged.
	require.Equal(dc.block0.Root(), got.Root(), "block 0 state root frozen")
	gotChild := rawdb.ReadBlock(dc.db, dc.block1.Hash(), dc.block1.NumberU64())
	require.NotNil(gotChild)
	require.Equal(dc.block1.Root(), gotChild.Root(), "block 1 state root frozen")

	// The digest in state is still D, and a verifier uses the public key read
	// from the contract's own storage to confirm the collision.
	postState, err := bc2.StateAt(dc.block1.Root())
	require.NoError(err)
	require.Equal(digest, redactabledeposit.GetDigest(postState, depositAddr, id), "digest in state unchanged")
	publishedPK := redactabledeposit.GetPublicKey(postState, depositAddr)
	require.Equal(hk.Bytes(), publishedPK, "authority public key readable from contract storage")
	verifierKey, err := chameleon.PublicKeyFromBytes(publishedPK)
	require.NoError(err)
	require.True(chameleon.Verify(verifierKey, blobPrime, rPrime, digest))

	require.NoError(bc2.ValidateCanonicalChain())
}

// TestChameleonConsensusRejectsTamperedRedaction: the content check rejects a
// redacted block whose opening doesn't commit to D, even if the roots/old-link are fine.
func TestChameleonConsensusRejectsTamperedRedaction(t *testing.T) {
	require := require.New(t)

	hk, _, err := chameleon.KeyGen()
	require.NoError(err)
	blob := bytes.Repeat([]byte{0xAB, 0xCD, 0xEF, 0x12}, 256)
	r := bytes.Repeat([]byte{0x07}, 32)
	digest := chameleon.Hash(hk, blob, r)
	id := crypto.Keccak256Hash([]byte("deposit-1"))

	dc := setupDepositChain(t, hk.Bytes(), id, blob, r, digest)

	// Tamper: redact with a garbage r' that does NOT satisfy CH("", r') == D.
	garbageR := bytes.Repeat([]byte{0xBA, 0xD0}, 16)
	tamperedCalldata, err := redactabledeposit.RedactedStoreCalldata(dc.storeTx.Data(), []byte{}, garbageR)
	require.NoError(err)
	require.False(chameleon.Verify(hk, []byte{}, garbageR, digest))

	redacted := redact.RedactBlock(dc.block0, dc.newTxsWithRedactedStore(dc.redactedStoreTx(t, tamperedCalldata)))
	require.NoError(redact.Persist(dc.db, dc.block0.Hash(), redacted))
	dc.bc.Stop()

	bc2, err := createBlockChain(dc.db, DefaultCacheConfig, dc.gspec, dc.block1.Hash())
	require.NoError(err)
	defer bc2.Stop()

	// Without the verifier, the tampered block still passes root/old-link checks.
	require.NoError(bc2.ValidateCanonicalChain())

	// With the verifier installed, validation rejects it.
	bc2.SetRedactionContentVerifier(redactabledeposit.VerifyRedactedBlock)
	require.Error(bc2.ValidateCanonicalChain(), "tampered redaction must be rejected at validation")
}

// TestChameleonRedactStoredEnforcesOpening: with the verifier on, RedactStored
// refuses a bad opening and accepts a correctly forged one.
func TestChameleonRedactStoredEnforcesOpening(t *testing.T) {
	require := require.New(t)

	hk, tk, err := chameleon.KeyGen()
	require.NoError(err)
	blob := bytes.Repeat([]byte{0xAB, 0xCD, 0xEF, 0x12}, 256)
	r := bytes.Repeat([]byte{0x07}, 32)
	digest := chameleon.Hash(hk, blob, r)
	id := crypto.Keccak256Hash([]byte("deposit-1"))

	dc := setupDepositChain(t, hk.Bytes(), id, blob, r, digest)
	defer dc.bc.Stop()
	dc.bc.SetRedactionContentVerifier(redactabledeposit.VerifyRedactedBlock)

	// Tampered opening: RedactStored refuses to apply it.
	garbageCalldata, err := redactabledeposit.RedactedStoreCalldata(dc.storeTx.Data(), []byte{}, bytes.Repeat([]byte{0xBA}, 32))
	require.NoError(err)
	_, err = dc.bc.RedactStored(dc.block0, dc.newTxsWithRedactedStore(dc.redactedStoreTx(t, garbageCalldata)), []byte("proof"))
	require.Error(err, "RedactStored must refuse an invalid opening")

	// Correctly forged opening: RedactStored applies it.
	rPrime, err := chameleon.Forge(tk, blob, r, []byte{})
	require.NoError(err)
	validCalldata, err := redactabledeposit.RedactedStoreCalldata(dc.storeTx.Data(), []byte{}, rPrime)
	require.NoError(err)
	_, err = dc.bc.RedactStored(dc.block0, dc.newTxsWithRedactedStore(dc.redactedStoreTx(t, validCalldata)), []byte("proof"))
	require.NoError(err, "RedactStored must accept a valid forged opening")
}

// TestChameleonForgeRejectedWithoutVote covers the negative gate cases.
func TestChameleonForgeRejectedWithoutVote(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	hk, tk, err := chameleon.KeyGen()
	require.NoError(err)
	blob := []byte("the secret blob to redact")
	r := bytes.Repeat([]byte{0x07}, 32)
	digest := chameleon.Hash(hk, blob, r)
	blobPrime := []byte{}

	sp := &redact.StateProposal{
		OriginalHash: common.Hash{0x01},
		DepositAddr:  common.Address{0x0d},
		ID:           crypto.Keccak256Hash([]byte("deposit-1")),
		Digest:       digest,
		NewBlobHash:  crypto.Keccak256Hash(blobPrime),
		PChainHeight: 1,
	}

	networkID := constants.UnitTestID
	sourceChainID := ids.GenerateTestID()
	ws, byIndex := buildCommittee(t, 3)
	warpSet := func(context.Context, uint64) (validators.WarpSet, error) { return ws, nil }

	// (a) No proof stored -> no vote -> no forge.
	noProofDB := rawdb.NewMemoryDatabase()
	noVote := redact.NewForger(redact.NewCommitteeStatePolicy(noProofDB, warpSet, networkID, sourceChainID, 2, 3), tk)
	_, err = noVote.Forge(ctx, sp, blob, r, blobPrime)
	require.ErrorIs(err, redact.ErrForgeNotApproved)

	// (b) Proof signed by only 1 of 3 -> below the 2/3 quorum -> rejected.
	lowDB := rawdb.NewMemoryDatabase()
	low := signStateProof(t, networkID, sourceChainID, sp, byIndex, 0)
	lowBytes, err := low.Bytes()
	require.NoError(err)
	require.NoError(redact.WriteStateRedactionProof(lowDB, sp.Hash(), lowBytes))
	belowQuorum := redact.NewForger(redact.NewCommitteeStatePolicy(lowDB, warpSet, networkID, sourceChainID, 2, 3), tk)
	_, err = belowQuorum.Forge(ctx, sp, blob, r, blobPrime)
	require.ErrorIs(err, redact.ErrForgeNotApproved)

	// (c) Approved vote, but a replacement blob other than the approved one.
	okDB := rawdb.NewMemoryDatabase()
	ok := signStateProof(t, networkID, sourceChainID, sp, byIndex, 0, 1, 2)
	okBytes, err := ok.Bytes()
	require.NoError(err)
	require.NoError(redact.WriteStateRedactionProof(okDB, sp.Hash(), okBytes))
	approved := redact.NewForger(redact.NewCommitteeStatePolicy(okDB, warpSet, networkID, sourceChainID, 2, 3), tk)
	_, err = approved.Forge(ctx, sp, blob, r, []byte("a different blob"))
	require.ErrorIs(err, redact.ErrForgeBlobMismatch)

	// Sanity: with the approved blob the forge succeeds.
	rPrime, err := approved.Forge(ctx, sp, blob, r, blobPrime)
	require.NoError(err)
	require.True(chameleon.Verify(hk, blobPrime, rPrime, digest))
}

// TestChameleonTamperedOpeningRejected: tampering with r' or blob' breaks the
// commitment, so any verifier checking CH(blob', r') == D rejects it.
func TestChameleonTamperedOpeningRejected(t *testing.T) {
	require := require.New(t)

	hk, tk, err := chameleon.KeyGen()
	require.NoError(err)
	blob := []byte("original content")
	r := bytes.Repeat([]byte{0x09}, 32)
	digest := chameleon.Hash(hk, blob, r)
	blobPrime := []byte{}

	rPrime, err := chameleon.Forge(tk, blob, r, blobPrime)
	require.NoError(err)
	require.True(chameleon.Verify(hk, blobPrime, rPrime, digest), "honest forge must verify")

	rTampered := bytes.Clone(rPrime)
	rTampered[0] ^= 0xFF
	require.False(chameleon.Verify(hk, blobPrime, rTampered, digest), "tampered r' must not verify")
	require.False(chameleon.Verify(hk, []byte("smuggled content"), rPrime, digest), "tampered blob' must not verify")
}
