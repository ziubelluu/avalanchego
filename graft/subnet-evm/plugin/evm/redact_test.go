// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package evm

import (
	"bytes"
	"context"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core/types"
	"github.com/ava-labs/libevm/crypto"
	"github.com/stretchr/testify/require"

	"github.com/ava-labs/avalanchego/graft/evm/utils"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/core"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/params"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/params/extras"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/params/paramstest"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/precompile/contracts/chameleonhash"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact/chameleon"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact/redactabledeposit"
	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/snow/validators"
	"github.com/ava-labs/avalanchego/snow/validators/validatorstest"
	"github.com/ava-labs/avalanchego/upgrade"
	"github.com/ava-labs/avalanchego/upgrade/upgradetest"
	"github.com/ava-labs/avalanchego/utils/crypto/bls"
	"github.com/ava-labs/avalanchego/utils/crypto/bls/signer/localsigner"
	"github.com/ava-labs/avalanchego/utils/set"
	"github.com/ava-labs/avalanchego/vms/components/chain"
	"github.com/ava-labs/avalanchego/vms/platformvm/warp"
)

// redactCommittee is three validators with BLS keys, plugged into the VM as
// the subnet validator set, so the real policy and the real forger can be
// exercised on a VM.
type redactCommittee struct {
	ws      validators.WarpSet
	byIndex map[int]bls.Signer
}

func newRedactCommittee(t *testing.T, vm *VM) *redactCommittee {
	t.Helper()
	byPK := map[string]bls.Signer{}
	vdrSet := map[ids.NodeID]*validators.GetValidatorOutput{}
	for i := 0; i < 3; i++ {
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

	// Only the warp validator set is ours, the rest still goes to the state the
	// harness gave the VM (the VM needs it to start again after a restart).
	prev := vm.ctx.ValidatorState
	vm.ctx.ValidatorState = &validatorstest.State{
		GetWarpValidatorSetsF: func(context.Context, uint64) (map[ids.ID]validators.WarpSet, error) {
			return map[ids.ID]validators.WarpSet{vm.ctx.SubnetID: ws}, nil
		},
		GetMinimumHeightF:       prev.GetMinimumHeight,
		GetCurrentHeightF:       prev.GetCurrentHeight,
		GetSubnetIDF:            prev.GetSubnetID,
		GetValidatorSetF:        prev.GetValidatorSet,
		GetCurrentValidatorSetF: prev.GetCurrentValidatorSet,
	}
	return &redactCommittee{ws: ws, byIndex: byIndex}
}

// signState signs a deposit proposal with the members in [signers].
func (c *redactCommittee) signState(t *testing.T, vm *VM, sp *redact.StateProposal, signers ...int) []byte {
	t.Helper()
	msg, err := warp.NewUnsignedMessage(vm.ctx.NetworkID, vm.ctx.ChainID, sp.Bytes())
	require.NoError(t, err)

	bits := set.NewBits()
	sigs := make([]*bls.Signature, 0, len(signers))
	for _, idx := range signers {
		sig, err := c.byIndex[idx].Sign(msg.Bytes())
		require.NoError(t, err)
		sigs = append(sigs, sig)
		bits.Add(idx)
	}
	aggSig, err := bls.AggregateSignatures(sigs)
	require.NoError(t, err)

	proof := &redact.StateProof{Proposal: *sp, SignerBitSet: bits.Bytes()}
	copy(proof.AggSignature[:], bls.SignatureToBytes(aggSig))
	raw, err := proof.Bytes()
	require.NoError(t, err)
	return raw
}

// vmDeposit is a VM where the deposit contract is deployed and one deposit
// (blob, r) is stored, with the block that holds the store tx.
type vmDeposit struct {
	tvm         *testVM
	committee   *redactCommittee
	hk          chameleon.PublicKey
	tk          chameleon.Trapdoor
	depositAddr common.Address
	id          common.Hash
	blob, r     []byte
	digest      []byte
	block       *types.Block
}

// sendAndAccept puts a dynamic-fee tx in the pool, builds a block with it,
// accepts it and returns the block.
func sendAndAccept(t *testing.T, vm *VM, nonce uint64, to *common.Address, gas uint64, data []byte) *types.Block {
	t.Helper()
	tx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{
		ChainID:   vm.chainConfig.ChainID,
		Nonce:     nonce,
		GasTipCap: big.NewInt(1_000_000_000),
		GasFeeCap: big.NewInt(225_000_000_000),
		Gas:       gas,
		To:        to,
		Data:      data,
	}), types.LatestSigner(vm.chainConfig), testKeys[0].ToECDSA())
	require.NoError(t, err)
	for _, err := range vm.txPool.AddRemotesSync([]*types.Transaction{tx}) {
		require.NoError(t, err)
	}
	blk := issueAndAccept(t, vm)
	ethBlock := blk.(*chain.BlockWrapper).Block.(*wrappedBlock).ethBlock
	receipts := vm.blockChain.GetReceiptsByHash(ethBlock.Hash())
	require.Len(t, receipts, 1)
	require.Equal(t, types.ReceiptStatusSuccessful, receipts[0].Status)
	return ethBlock
}

func setupVMDeposit(t *testing.T) *vmDeposit {
	t.Helper()
	require := require.New(t)

	genesis := &core.Genesis{}
	require.NoError(genesis.UnmarshalJSON([]byte(toGenesisJSON(paramstest.ForkToChainConfig[upgradetest.Latest]))))
	params.GetExtra(genesis.Config).GenesisPrecompiles = extras.Precompiles{
		chameleonhash.ConfigKey: chameleonhash.NewConfig(utils.TimeToNewUint64(upgrade.InitiallyActiveTime)),
	}
	genesisJSON, err := genesis.MarshalJSON()
	require.NoError(err)
	tvm := newVM(t, testVMConfig{genesisJSON: string(genesisJSON)})
	t.Cleanup(func() { require.NoError(tvm.vm.Shutdown(context.Background())) })
	vm := tvm.vm

	hk, tk, err := chameleon.KeyGen()
	require.NoError(err)
	t.Setenv(RedactTrapdoorEnvVar, hex.EncodeToString(tk.Bytes()))

	code, err := redactabledeposit.DeployCode(hk.Bytes())
	require.NoError(err)
	depositAddr := crypto.CreateAddress(testEthAddrs[0], 0)
	sendAndAccept(t, vm, 0, nil, 1_500_000, code)

	blob := bytes.Repeat([]byte{0xAB, 0xCD, 0xEF, 0x12}, 256)
	r, err := chameleon.NewRandomness()
	require.NoError(err)
	digest := chameleon.Hash(hk, blob, r)
	id := crypto.Keccak256Hash([]byte("deposit-1"))
	calldata, err := redactabledeposit.PackStore(id, blob, r, digest)
	require.NoError(err)
	block := sendAndAccept(t, vm, 1, &depositAddr, 3_000_000, calldata)

	statedb, err := vm.blockChain.State()
	require.NoError(err)
	require.Equal(digest, redactabledeposit.GetDigest(statedb, depositAddr, id), "the deposit must be committed")

	return &vmDeposit{
		tvm: tvm, committee: newRedactCommittee(t, vm), hk: hk, tk: tk,
		depositAddr: depositAddr, id: id, blob: blob, r: r, digest: digest, block: block,
	}
}

func (d *vmDeposit) proposal(blobPrime []byte) *redact.StateProposal {
	return &redact.StateProposal{
		OriginalHash: d.block.Hash(),
		DepositAddr:  d.depositAddr,
		ID:           d.id,
		Digest:       d.digest,
		NewBlobHash:  crypto.Keccak256Hash(blobPrime),
		PChainHeight: 1,
	}
}

// TestRedactStateDepositRejectsInvalidProofWithoutWriting: with a proof that
// doesn't reach the quorum, RedactStateDeposit fails and leaves no trace in
// the database, neither for the proposal nor for the block.
func TestRedactStateDepositRejectsInvalidProofWithoutWriting(t *testing.T) {
	require := require.New(t)
	d := setupVMDeposit(t)
	vm := d.tvm.vm

	blobPrime := []byte{}
	sp := d.proposal(blobPrime)
	belowQuorum := d.committee.signState(t, vm, sp, 0) // 1 of 3

	_, _, err := vm.RedactStateDeposit(context.Background(), d.block.Hash(), d.depositAddr, d.id, d.blob, d.r, blobPrime, belowQuorum, 1)
	require.Error(err, "a proof below the quorum must be refused")

	_, err = redact.ReadStateRedactionProof(vm.chaindb, sp.Hash())
	require.Error(err, "no proof must be stored for the proposal")
	has, err := redact.HasRedactionProof(vm.chaindb, d.block.Hash())
	require.NoError(err)
	require.False(has, "no proof must be stored for the block")

	got := vm.blockChain.GetBlockByHash(d.block.Hash())
	require.NotNil(got)
	require.Equal(d.block.TxHash(), got.TxHash(), "the block must not change")
}

// TestRedactStateDepositAppliesApprovedRedaction: the whole thing on a VM,
// with the committee, the trapdoor from the environment and the real policy.
func TestRedactStateDepositAppliesApprovedRedaction(t *testing.T) {
	require := require.New(t)
	d := setupVMDeposit(t)
	vm := d.tvm.vm

	blobPrime := []byte{}
	sp := d.proposal(blobPrime)
	approved := d.committee.signState(t, vm, sp, 0, 1, 2)

	redactedHash, rPrime, err := vm.RedactStateDeposit(context.Background(), d.block.Hash(), d.depositAddr, d.id, d.blob, d.r, blobPrime, approved, 1)
	require.NoError(err)
	require.NotEqual(d.block.Hash(), redactedHash)
	require.True(chameleon.Verify(d.hk, blobPrime, rPrime, d.digest), "the new opening must still give the digest")

	got := vm.blockChain.GetBlockByHash(d.block.Hash())
	require.NotNil(got)
	storeTx, ok := redactabledeposit.FindStoreTx(got, d.depositAddr, d.id)
	require.True(ok)
	_, gotBlob, gotR, gotDigest, err := redactabledeposit.UnpackStoreInput(storeTx.Data()[4:])
	require.NoError(err)
	require.Empty(gotBlob)
	require.Equal(rPrime, gotR)
	require.Equal(d.digest, gotDigest)

	// The policy the VM installed accepts the redacted block.
	require.NoError(vm.blockChain.ValidateCanonicalChain())
}

// TestRedactStateDepositTrapdoorFromFile: the trapdoor can also come from the
// file named in the chain config, when the env var is not set.
func TestRedactStateDepositTrapdoorFromFile(t *testing.T) {
	require := require.New(t)
	d := setupVMDeposit(t)
	vm := d.tvm.vm
	t.Setenv(RedactTrapdoorEnvVar, "")

	blobPrime := []byte{}
	sp := d.proposal(blobPrime)
	approved := d.committee.signState(t, vm, sp, 0, 1, 2)
	redactNow := func() error {
		_, _, err := vm.RedactStateDeposit(context.Background(), d.block.Hash(), d.depositAddr, d.id, d.blob, d.r, blobPrime, approved, 1)
		return err
	}

	require.Error(redactNow(), "no env var and no file: this node can't forge")

	path := filepath.Join(t.TempDir(), "trapdoor")
	require.NoError(os.WriteFile(path, []byte(hex.EncodeToString(d.tk.Bytes())+"\n"), 0o600))
	vm.config.RedactTrapdoorFile = path
	require.NoError(redactNow())

	got := vm.blockChain.GetBlockByHash(d.block.Hash())
	require.NotNil(got)
	require.True(redact.IsRedacted(got.Header()))
}
