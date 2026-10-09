# Live redaction walkthrough

Runs a redaction on a real local network through the admin RPC: a deposit in
the `RedactableDeposit` contract gets its content erased while the digest in
state, the state roots and the block number stay the same.

Files here: `redactlive_main.go` (helper, build tag `none`, never built by
`go build ./...`), `chain-genesis.json` (test genesis plus
`chameleonHashConfig` from block 0), `chain-config.json` (admin and warp API
on; `start --trapdoor-file` adds `redact-trapdoor-file` to it), `subnet-evm-wrapper.sh` (another way to give the trapdoor to the plugin).

You need Go, `curl`, and a few minutes. Values in `$CAPS` are copied by hand
from the output of the step before.

## 1. Build

```bash
# from the repository root
./scripts/build.sh
./graft/subnet-evm/scripts/build.sh "$PWD/build/subnet-evm"
./scripts/build_tmpnetctl.sh
cd graft/subnet-evm
rl()  { go run ./examples/redact-live/redactlive_main.go "$@"; }
rpc() { curl -s -X POST -H 'content-type: application/json' \
        --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}" "$3"; }
```

## 2. Authority keys and plugin dir

```bash
rl keygen            # -> publicKey ($HK), trapdoor
mkdir -p /tmp/redact-live/plugins
(umask 077; echo "<the trapdoor>" > /tmp/redact-live/trapdoor)
ln -s "$PWD/../../build/subnet-evm" \
   /tmp/redact-live/plugins/srEXiWaHuhNyGwPUi444Tu47ZEDwxTWrbQiuD7FmgSAQ6X7Dy
```

The plugin reads the trapdoor from the file named by `redact-trapdoor-file` in
the chain config. On this local network both nodes get the same chain config
and so the same file; on a real network only the authority has it.

The other way is the `SUBNET_EVM_REDACT_TRAPDOOR` variable, but it has to be
set in the plugin process (avalanchego does not pass its own environment to
the VM): `subnet-evm-wrapper.sh` does that, copied into the plugin dir instead
of the link. The variable wins over the file.

## 3. Start the network (two nodes)

```bash
rl start --avalanchego "$PWD/../../build/avalanchego" \
         --plugin-dir /tmp/redact-live/plugins --root-dir /tmp/redact-live/root \
         --trapdoor-file /tmp/redact-live/trapdoor
# -> networkDir, chainID ($CHAIN), two node uris ($URI1 is the authority, $URI2)
RPC=$URI1/ext/bc/$CHAIN/rpc
ADMIN1=$URI1/ext/bc/$CHAIN/admin; ADMIN2=$URI2/ext/bc/$CHAIN/admin
```

Two nodes are needed because with a single node tmpnet turns sybil protection
off, and then the node only sees the validator set of the primary network: the
subnet has no Warp validator set and no proof can be collected.

## 4. Deploy and deposit

```bash
rl deploy-tx --hk $HK                                   # -> rawTx, contract ($CONTRACT)
rpc eth_sendRawTransaction "[\"$RAW\"]" $RPC
ID=0x$(printf 'deposit-1' | sha256sum | cut -c1-64)
rl hash --hk $HK --blob "some private text"              # -> digest ($D), randomness ($RS)
rl store-tx --to $CONTRACT --id $ID --blob "some private text" --rs $RS --digest $D
rpc eth_sendRawTransaction "[\"$RAW\"]" $RPC            # -> store tx hash ($TX)
rpc eth_getTransactionReceipt "[\"$TX\"]" $RPC          # -> blockHash ($BLOCK)
rpc eth_getTransactionByHash "[\"$TX\"]" $RPC           # the text is readable in "input"
```

## 5. Approve on both nodes, collect, redact

```bash
rpc platform.getHeight '{}' $URI1/ext/bc/P              # -> height ($H)
rl state-proposal --block $BLOCK --contract $CONTRACT --id $ID --digest $D \
                  --newblob "" --pchain $H              # -> proposal ($SP)
rpc admin.approveRedaction "{\"kind\":\"state\",\"proposal\":\"$SP\"}" $ADMIN1
rpc admin.approveRedaction "{\"kind\":\"state\",\"proposal\":\"$SP\"}" $ADMIN2
rpc admin.collectRedactionProof "{\"kind\":\"state\",\"proposal\":\"$SP\"}" $ADMIN1   # -> proof ($PROOF)
# with only one of the two approvals this call fails: "not enough validators signed the proposal"
rpc admin.redactStateDeposit "{\"originalBlockHash\":\"$BLOCK\",\"depositContract\":\"$CONTRACT\",
  \"depositID\":\"$ID\",\"blob\":\"0x$(printf 'some private text' | xxd -p | tr -d '\n')\",
  \"randomness\":\"0x$RS\",\"newBlob\":\"0x\",\"proof\":\"$PROOF\",\"pChainHeight\":$H}" $ADMIN1
```

## 6. Read back

```bash
rpc eth_getBlockByHash "[\"$BLOCK\",true]" $RPC   # same number and stateRoot, new transactionsRoot,
                                                  # initialTransactionsRoot is the one from before
rl decode-store --calldata <input of the store tx>   # empty blob, new randomness, same digest
rpc eth_call "[{\"to\":\"$CONTRACT\",\"data\":\"$(rl digestof-calldata --id $ID)\"},\"latest\"]" $RPC
rl decode-digestof --output <result>                  # still $D
```

The block is still found under `$BLOCK`, its original hash, and the `hash`
field in the answer is the new one. A block is redacted when
`transactionsRoot` and `initialTransactionsRoot` differ. The old tx hash is
gone.

## 7. Restart, new blocks, stop

```bash
../../build/tmpnetctl restart-network --network-dir <networkDir>   # ports change, see process.json
rl plain-tx --nonce 2 --data "one more block"
rpc eth_sendRawTransaction "[\"$RAW\"]" $RPC      # the new block has parentHash = $BLOCK
../../build/tmpnetctl stop-network    --network-dir <networkDir>
```

After the restart the same reads give the same answers, also when the
redacted block is the tip of the chain, and both nodes keep accepting the new
blocks.

## Known limits

- Only the node that gets the `admin.redact*` call applies the redaction. The
  other node keeps the original block: here `$URI2` still shows the text.
- The redaction clears the Subnet-EVM database (`chainData/`). The original
  block bytes are still in the node database (`db/`), where the ProposerVM
  keeps its own copy of every block. `start --proposer-history N` makes it
  keep only the last N blocks, but in our run with N=2 and four blocks on top
  the text was still in a table file of the database:
  `grep -rla "some private text" <networkDir>/NodeID-*/db`.
- Same for `chainData/` in general: the databases delete by writing a marker,
  the old bytes leave the disk only when the files get compacted.
- A node that joins later and syncs from the others gets whatever copy they
  give it; it has no way yet to ask for the proof of a redacted block.

## Tx channel

Same steps with `kind` `tx`: `rl plain-tx --data "some text"`, then
`rl tx-proposal --rpc $RPC --block $BLOCK --indices 0 --pchain $H`, approve on
both nodes, collect, and
`rpc admin.redactTransactions "{\"originalBlockHash\":\"$BLOCK\",\"proof\":\"$PROOF\"}" $ADMIN1`.
The calldata at that position becomes `0x`.
