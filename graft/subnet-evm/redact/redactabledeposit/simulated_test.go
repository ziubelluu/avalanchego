// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redactabledeposit_test

import (
	"bytes"
	"crypto/ecdsa"
	"math/big"
	"os"
	"testing"

	ethereum "github.com/ava-labs/libevm"
	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core/types"
	"github.com/ava-labs/libevm/crypto"
	"github.com/stretchr/testify/require"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/core"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/params"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/plugin/evm/customtypes"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/precompile/contracts/chameleonhash"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact/redactabledeposit"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/precompile/contracts/utilstest"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact/chameleon"
	"github.com/ava-labs/avalanchego/utils"

	sim "github.com/ava-labs/avalanchego/graft/subnet-evm/ethclient/simulated"
)

func TestMain(m *testing.M) {
	core.RegisterExtras()
	customtypes.Register()
	params.RegisterExtras()
	os.Exit(m.Run())
}

// sendTx signs and submits a transaction, returning it.
func sendTx(t *testing.T, b *sim.Backend, key *ecdsa.PrivateKey, nonce uint64, to *common.Address, data []byte) *types.Transaction {
	t.Helper()
	ctx := t.Context()
	client := b.Client()
	chainID, err := client.ChainID(ctx)
	require.NoError(t, err)
	head, err := client.HeaderByNumber(ctx, nil)
	require.NoError(t, err)
	tx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		GasTipCap: big.NewInt(params.GWei),
		GasFeeCap: new(big.Int).Add(head.BaseFee, big.NewInt(params.GWei)),
		Gas:       3_000_000,
		To:        to,
		Data:      data,
	}), types.LatestSignerForChainID(chainID), key)
	require.NoError(t, err)
	require.NoError(t, client.SendTransaction(ctx, tx))
	return tx
}

// deployDeposit deploys a RedactableDeposit contract with authority key [hk] and
// returns its address.
func deployDeposit(t *testing.T, b *sim.Backend, key *ecdsa.PrivateKey, nonce uint64, hk []byte) common.Address {
	t.Helper()
	code, err := redactabledeposit.DeployCode(hk)
	require.NoError(t, err)
	tx := sendTx(t, b, key, nonce, nil, code)
	receipt := utilstest.WaitReceiptSuccessful(t, b, tx)
	require.NotEqual(t, common.Address{}, receipt.ContractAddress)
	return receipt.ContractAddress
}

// TestStoreCommitsDigestOffStateBlob deploys the deposit contract (with the
// chameleon precompile on), stores a (blob, r), and checks the digest is saved
// while the opening stays only in calldata, never in storage or the event.
func TestStoreCommitsDigestOffStateBlob(t *testing.T) {
	require := require.New(t)
	ctx := t.Context()

	key, err := crypto.GenerateKey()
	require.NoError(err)
	addr := crypto.PubkeyToAddress(key.PublicKey)

	hk, _, err := chameleon.KeyGen()
	require.NoError(err)

	backend := utilstest.NewBackendWithPrecompile(t, chameleonhash.NewConfig(utils.PointerTo[uint64](0)), []common.Address{addr})
	defer backend.Close()
	client := backend.Client()

	depositAddr := deployDeposit(t, backend, key, 0, hk.Bytes())

	blob := bytes.Repeat([]byte{0xAB, 0xCD, 0xEF, 0x12}, 256)
	r := bytes.Repeat([]byte{0x07}, 32)
	digest := chameleon.Hash(hk, blob, r)
	require.Len(digest, redactabledeposit.DigestLen)
	id := crypto.Keccak256Hash([]byte("deposit-1"))

	calldata, err := redactabledeposit.PackStore(id, blob, r, digest)
	require.NoError(err)
	tx := sendTx(t, backend, key, 1, &depositAddr, calldata)
	receipt := utilstest.WaitReceiptSuccessful(t, backend, tx)

	// 1) digestOf(id) returns exactly D.
	digestOfCalldata, err := redactabledeposit.PackDigestOf(id)
	require.NoError(err)
	out, err := client.CallContract(ctx, ethereum.CallMsg{To: &depositAddr, Data: digestOfCalldata}, nil)
	require.NoError(err)
	gotDigest, err := redactabledeposit.UnpackDigestOfOutput(out)
	require.NoError(err)
	require.Equal(digest, gotDigest, "stored digest must equal CH(blob, r)")

	// 2) GetDigest reads the same digest straight from contract storage.
	require.NotEmpty(receipt.Logs)
	log := receipt.Logs[0]
	require.Equal(depositAddr, log.Address)
	require.Equal(id, common.Hash(log.Topics[1]), "indexed id topic")
	ev, err := redactabledeposit.UnpackDepositedEventData(log.Data)
	require.NoError(err)
	require.Equal(digest, ev.Digest)
	require.False(bytes.Contains(log.Data, blob), "blob must not be in the event/receipt")
	require.False(bytes.Contains(log.Data, r), "randomness must not be in the event/receipt")

	// 3) The opening (blob, r) lives only in the tx calldata.
	require.True(bytes.Contains(tx.Data(), blob), "blob travels in calldata (off-state)")
	require.True(bytes.Contains(tx.Data(), r), "randomness travels in calldata (off-state)")
	require.Less(len(digest), len(blob))
}

// TestStoreRejectsInvalidOpening checks the verify-on-store: a deposit whose
// opening doesn't match the digest reverts (the contract calls the precompile
// and compares).
func TestStoreRejectsInvalidOpening(t *testing.T) {
	require := require.New(t)

	key, err := crypto.GenerateKey()
	require.NoError(err)
	addr := crypto.PubkeyToAddress(key.PublicKey)

	hk, _, err := chameleon.KeyGen()
	require.NoError(err)

	backend := utilstest.NewBackendWithPrecompile(t, chameleonhash.NewConfig(utils.PointerTo[uint64](0)), []common.Address{addr})
	defer backend.Close()

	depositAddr := deployDeposit(t, backend, key, 0, hk.Bytes())

	blob := bytes.Repeat([]byte{0xAB}, 64)
	r := bytes.Repeat([]byte{0x07}, 32)
	bogusDigest := bytes.Repeat([]byte{0xFF}, redactabledeposit.DigestLen)
	require.NotEqual(chameleon.Hash(hk, blob, r), bogusDigest)
	id := crypto.Keccak256Hash([]byte("bad-deposit"))

	calldata, err := redactabledeposit.PackStore(id, blob, r, bogusDigest)
	require.NoError(err)
	tx := sendTx(t, backend, key, 1, &depositAddr, calldata)
	receipt := utilstest.WaitReceipt(t, backend, tx)
	require.Equal(types.ReceiptStatusFailed, receipt.Status, "store with an invalid opening must revert")
}

// TestStoreIsWriteOncePerID: a second store on the same id reverts. This keeps D
// immutable, which the pruned-safe check needs (reading D at head is the same
// as reading it at the redacted block), and it stops someone from overwriting D
// to break a future redaction.
func TestStoreIsWriteOncePerID(t *testing.T) {
	require := require.New(t)

	key, err := crypto.GenerateKey()
	require.NoError(err)
	addr := crypto.PubkeyToAddress(key.PublicKey)

	hk, _, err := chameleon.KeyGen()
	require.NoError(err)

	backend := utilstest.NewBackendWithPrecompile(t, chameleonhash.NewConfig(utils.PointerTo[uint64](0)), []common.Address{addr})
	defer backend.Close()

	depositAddr := deployDeposit(t, backend, key, 0, hk.Bytes())

	blob := bytes.Repeat([]byte{0xAB}, 64)
	r := bytes.Repeat([]byte{0x07}, 32)
	digest := chameleon.Hash(hk, blob, r)
	id := crypto.Keccak256Hash([]byte("deposit-1"))

	calldata, err := redactabledeposit.PackStore(id, blob, r, digest)
	require.NoError(err)

	// First store succeeds.
	tx1 := sendTx(t, backend, key, 1, &depositAddr, calldata)
	require.Equal(types.ReceiptStatusSuccessful, utilstest.WaitReceipt(t, backend, tx1).Status)

	// Second store on the same id reverts (write-once).
	tx2 := sendTx(t, backend, key, 2, &depositAddr, calldata)
	require.Equal(types.ReceiptStatusFailed, utilstest.WaitReceipt(t, backend, tx2).Status, "reusing an id must revert")
}
