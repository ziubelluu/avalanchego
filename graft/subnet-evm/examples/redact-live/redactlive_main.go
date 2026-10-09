// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build none

/*
redactlive is the helper for the live redaction walkthrough in README.md. It
only does what curl can't: start a local tmpnet network with a Subnet-EVM
subnet, make the authority keys, sign transactions and encode proposals.
Everything else in the walkthrough goes through the node's RPC.

It is not part of the normal build. Run it from graft/subnet-evm with:

	go run ./examples/redact-live/redactlive_main.go <subcommand> [flags]
*/
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ava-labs/libevm/common"
	"github.com/ava-labs/libevm/core/types"
	"github.com/ava-labs/libevm/crypto"
	"github.com/ava-labs/libevm/trie"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/core"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/ethclient"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/params"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/params/extras"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/plugin/evm"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/precompile/contracts/chameleonhash"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact/chameleon"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/redact/redactabledeposit"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/tests"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/tests/utils"
	"github.com/ava-labs/avalanchego/tests/fixture/tmpnet"

	agotests "github.com/ava-labs/avalanchego/tests"
	agoutils "github.com/ava-labs/avalanchego/utils"
)

const subcommands = "start genesis keygen hash deploy-tx store-tx plain-tx decode-store digestof-calldata decode-digestof state-proposal tx-proposal"

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func hexArg(s string) []byte {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	must(err)
	return b
}

func out(v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

func main() {
	// same registration the plugin does, or headers and blocks don't decode
	evm.RegisterAllLibEVMExtras()
	if len(os.Args) < 2 {
		fmt.Println("subcommands:", subcommands)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	switch cmd {
	case "start":
		start(fs, args)
	case "genesis":
		must(fs.Parse(args))
		fmt.Println(string(chainGenesis()))
	case "keygen":
		// the authority key pair: the public key goes in the contract, the
		// trapdoor only on the authority node
		must(fs.Parse(args))
		hk, tk, err := chameleon.KeyGen()
		must(err)
		out(map[string]string{"publicKey": hex.EncodeToString(hk.Bytes()), "trapdoor": hex.EncodeToString(tk.Bytes())})
	case "hash":
		// the digest and the randomness come out together: the randomness is
		// a proof about the digest, so it can't be picked first
		hk := fs.String("hk", "", "authority public key, hex")
		blob := fs.String("blob", "", "content, utf8 text")
		must(fs.Parse(args))
		pk, err := chameleon.PublicKeyFromBytes(hexArg(*hk))
		must(err)
		digest, rs, err := chameleon.Hash(pk, []byte(*blob))
		must(err)
		out(map[string]string{"digest": hex.EncodeToString(digest), "randomness": hex.EncodeToString(rs)})
	case "deploy-tx":
		chainID := fs.Int64("chainid", 99999, "")
		nonce := fs.Uint64("nonce", 0, "")
		hk := fs.String("hk", "", "authority public key, hex")
		must(fs.Parse(args))
		code, err := redactabledeposit.DeployCode(hexArg(*hk))
		must(err)
		raw, from := signTx(*chainID, *nonce, nil, 1_500_000, code)
		out(map[string]string{"rawTx": raw, "from": from.Hex(), "contract": crypto.CreateAddress(from, *nonce).Hex()})
	case "store-tx":
		chainID := fs.Int64("chainid", 99999, "")
		nonce := fs.Uint64("nonce", 1, "")
		to := fs.String("to", "", "deposit contract address")
		id := fs.String("id", "", "deposit id, hex 32 bytes")
		blob := fs.String("blob", "", "content, utf8 text")
		rs := fs.String("rs", "", "randomness, hex")
		digest := fs.String("digest", "", "digest, hex")
		must(fs.Parse(args))
		calldata, err := redactabledeposit.PackStore(common.HexToHash(*id), []byte(*blob), hexArg(*rs), hexArg(*digest))
		must(err)
		toAddr := common.HexToAddress(*to)
		raw, _ := signTx(*chainID, *nonce, &toAddr, 3_000_000, calldata)
		out(map[string]string{"rawTx": raw, "calldataBytes": strconv.Itoa(len(calldata))})
	case "plain-tx":
		// a tx with some text in the calldata, to try the tx channel on
		chainID := fs.Int64("chainid", 99999, "")
		nonce := fs.Uint64("nonce", 2, "")
		data := fs.String("data", "", "utf8 text to put in the calldata")
		must(fs.Parse(args))
		to := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
		raw, _ := signTx(*chainID, *nonce, &to, 21000+16*uint64(len(*data))+10000, []byte(*data))
		out(map[string]string{"rawTx": raw})
	case "decode-store":
		calldata := fs.String("calldata", "", "store calldata, hex")
		must(fs.Parse(args))
		data := hexArg(*calldata)
		id, blob, rs, digest, err := redactabledeposit.UnpackStoreInput(data[4:])
		must(err)
		out(map[string]any{
			"id": id.Hex(), "blobBytes": len(blob), "blobUTF8": string(blob),
			"randomnessBytes": len(rs), "randomnessPrefix": hex.EncodeToString(rs[:16]) + "...",
			"digest": hex.EncodeToString(digest),
		})
	case "digestof-calldata":
		id := fs.String("id", "", "deposit id, hex 32 bytes")
		must(fs.Parse(args))
		cd, err := redactabledeposit.PackDigestOf(common.HexToHash(*id))
		must(err)
		fmt.Println("0x" + hex.EncodeToString(cd))
	case "decode-digestof":
		ret := fs.String("output", "", "eth_call result, hex")
		must(fs.Parse(args))
		d, err := redactabledeposit.UnpackDigestOfOutput(hexArg(*ret))
		must(err)
		fmt.Println(hex.EncodeToString(d))
	case "state-proposal":
		block := fs.String("block", "", "hash of the block with the store tx")
		contract := fs.String("contract", "", "deposit contract address")
		id := fs.String("id", "", "deposit id, hex 32 bytes")
		digest := fs.String("digest", "", "digest, hex")
		newBlob := fs.String("newblob", "", "new content, utf8 text (empty to erase)")
		pchain := fs.Uint64("pchain", 0, "P-Chain height of the validator set")
		must(fs.Parse(args))
		sp := &redact.StateProposal{
			OriginalHash: common.HexToHash(*block),
			DepositAddr:  common.HexToAddress(*contract),
			ID:           common.HexToHash(*id),
			Digest:       hexArg(*digest),
			NewBlobHash:  crypto.Keccak256Hash([]byte(*newBlob)),
			PChainHeight: *pchain,
		}
		out(map[string]string{"proposal": "0x" + hex.EncodeToString(sp.Bytes()), "proposalHash": sp.Hash().Hex(), "newBlobHash": sp.NewBlobHash.Hex()})
	case "tx-proposal":
		rpc := fs.String("rpc", "", "eth rpc url of the chain")
		block := fs.String("block", "", "hash of the block to redact")
		idx := fs.String("indices", "0", "positions to blank, comma separated")
		pchain := fs.Uint64("pchain", 0, "P-Chain height of the validator set")
		must(fs.Parse(args))
		client, err := ethclient.Dial(*rpc)
		must(err)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		blk, err := client.BlockByHash(ctx, common.HexToHash(*block))
		must(err)
		var indices []uint64
		newTxs := make([]*types.Transaction, len(blk.Transactions()))
		copy(newTxs, blk.Transactions())
		for _, s := range strings.Split(*idx, ",") {
			i, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
			must(err)
			indices = append(indices, i)
			tx, err := redact.RebuildTxWithData(newTxs[i], nil)
			must(err)
			newTxs[i] = tx
		}
		// The block hash is the one given on the command line: it's the old
		// link, the name the block keeps. The new tx root only depends on the
		// transactions.
		derivedOld := types.DeriveSha(types.Transactions(blk.Transactions()), trie.NewStackTrie(nil))
		newTxHash := types.DeriveSha(types.Transactions(newTxs), trie.NewStackTrie(nil))
		p := &redact.Proposal{OriginalHash: common.HexToHash(*block), NewTxHash: newTxHash, PChainHeight: *pchain, RedactedIndices: indices}
		out(map[string]string{
			"proposal": "0x" + hex.EncodeToString(p.Bytes()), "newTxHash": newTxHash.Hex(),
			"rpcTxRoot": blk.TxHash().Hex(), "txRootDerivedFromRpcTxs": derivedOld.Hex(),
		})
	default:
		fmt.Println("unknown subcommand", cmd)
		fmt.Println("subcommands:", subcommands)
		os.Exit(2)
	}
}

// signTx signs a dynamic-fee tx with the pre-funded tmpnet key and returns it
// ready for eth_sendRawTransaction.
func signTx(chainID int64, nonce uint64, to *common.Address, gas uint64, data []byte) (string, common.Address) {
	key := tmpnet.HardhatKey.ToECDSA()
	signer := types.LatestSignerForChainID(big.NewInt(chainID))
	tx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{
		ChainID:   big.NewInt(chainID),
		Nonce:     nonce,
		GasTipCap: big.NewInt(1_000_000_000),
		GasFeeCap: big.NewInt(50_000_000_000),
		Gas:       gas,
		To:        to,
		Data:      data,
	}), signer, key)
	must(err)
	raw, err := tx.MarshalBinary()
	must(err)
	return "0x" + hex.EncodeToString(raw), crypto.PubkeyToAddress(key.PublicKey)
}

// chainGenesis is the Subnet-EVM test genesis plus the chameleon hash
// precompile active from block 0. chain-genesis.json is this, printed.
func chainGenesis() []byte {
	genesis := &core.Genesis{}
	must(genesis.UnmarshalJSON(tests.Genesis))
	params.GetExtra(genesis.Config).GenesisPrecompiles = extras.Precompiles{
		chameleonhash.ConfigKey: chameleonhash.NewConfig(agoutils.PointerTo[uint64](0)),
	}
	b, err := genesis.MarshalJSON()
	must(err)
	return b
}

// chainConfig is what chain-config.json has: the admin API has the redaction
// calls, the warp API is needed to collect the signatures.
//
// On this local network every node gets the same chain config, so they all
// read the same trapdoor file. On a real network only the authority has it.
func chainConfig(trapdoorFile string) map[string]any {
	c := map[string]any{
		"admin-api-enabled": true,
		"local-txs-enabled": true,
		"warp-api-enabled":  true,
		"log-level":         "info",
	}
	if trapdoorFile != "" {
		c["redact-trapdoor-file"] = trapdoorFile
	}
	return c
}

// start boots a tmpnet network where every node validates one subnet running
// Subnet-EVM, and prints where to find it. The nodes keep running after this
// returns; stop them with tmpnetctl.
func start(fs *flag.FlagSet, args []string) {
	avago := fs.String("avalanchego", "", "path to the avalanchego binary")
	pluginDir := fs.String("plugin-dir", "", "dir with the VM binary (or its wrapper) named by VMID")
	rootDir := fs.String("root-dir", "", "where the network dir is created")
	// With one node tmpnet turns sybil protection off, and then the node
	// can't see the validator set of the subnet: no proof can be collected.
	nodeCount := fs.Int("nodes", 2, "number of nodes, all validators of the subnet (at least 2)")
	trapdoorFile := fs.String("trapdoor-file", "", "file with the authority trapdoor (hex), goes in the chain config")
	// The ProposerVM keeps its own copy of every block, with the original
	// bytes. With this set it only keeps the last N.
	history := fs.Uint64("proposer-history", 0, "blocks the ProposerVM keeps (0 = all)")
	must(fs.Parse(args))

	nodes := tmpnet.NewNodesOrPanic(*nodeCount)
	subnet := utils.NewTmpnetSubnet("redact", chainGenesis(), chainConfig(*trapdoorFile), nodes...)
	if *history > 0 {
		subnet.Config = tmpnet.ConfigMap{"proposerNumHistoricalBlocks": *history}
	}
	network := utils.NewTmpnetNetwork("redact-live", nodes, tmpnet.FlagsMap{}, subnet)
	network.DefaultRuntimeConfig = tmpnet.NodeRuntimeConfig{Process: &tmpnet.ProcessRuntimeConfig{
		AvalancheGoPath: *avago,
		PluginDir:       *pluginDir,
	}}

	log := agotests.NewDefaultLogger("redact-live")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	must(tmpnet.BootstrapNewNetwork(ctx, log, network, *rootDir))

	nodesOut := []map[string]string{}
	for _, n := range network.Nodes {
		nodesOut = append(nodesOut, map[string]string{"nodeID": n.NodeID.String(), "uri": n.GetAccessibleURI()})
	}
	out(map[string]any{
		"networkDir": network.Dir,
		"subnetID":   subnet.SubnetID.String(),
		"chainID":    subnet.Chains[0].ChainID.String(),
		"nodes":      nodesOut,
	})
}
