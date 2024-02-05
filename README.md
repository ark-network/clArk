rust-ark
========

An implementation of the Ark second-layer payment protocol for Bitcoin.

This repository comprises an ASP server, `arkd`, a client wallet, `noah`, and
a library that contains all the primitives used for these implementations.




# Demo

You can play around with the tools as follows:


First you have to setup a regtest bitcoind node, there is a script provided for
that. If you want to run your own node, keep in mind that for now, we need it
to have the txindex enabled.

```
$ ./run_bitcoind.sh
```

You can interact with the node using `bitcoin-cli` as follows:

```
$ bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass getnetworkinfo
```

Then, you can run an arkd server:

```
$ cargo run --bin arkd
```

This will start the server and it will work immediatelly. The configuration
currently is hard-coded in the `arkd/src/main.rs` file, and can only be changed
there. For arkd to work properly, you should fund it with some liquidity, this
can be done by sending some money to the address that is printed out when arkd
is started. You can send money there as follows:

```
$ bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass generatetoaddress 1 <asp-addr>
# Then give it 100 confirmations because it's a coinbase output.
$ bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass generatetoaddress 100 mtDDKi5mDjZqGzmbnfUnVQ8ZhCPMPVsApj
```

Next, you can start some clients. To create a client, use the following command:

```
$ cargo run --bin noah -- --datadir ./test/noah1 create
$ cargo run --bin noah -- --datadir ./test/noah2 create
```

These will create individual wallets and print an on-chain address you can use
to **fund them the same way as you did for the ASP above**. Note that clients
can receive off-chain Ark transactions without having any on-chain balance, but
a little bit of on-chain money is needed to perform unilateral exits.

To use the onchain wallets, there are a few commands available:

```
$ NOAH2_ADDR=$(cargo run --bin noah -- --datadir ./test/noah2 get-address)
$ cargo run --bin noah -- --datadir ./test/noah1 send-onchain $NOAH2_ADDR "0.1 btc"
$ cargo run --bin noah -- --datadir ./test/noah2 balance
```

Once we have money, we can onboard into the Ark, afterwards the balance will
also show an off-chain element.

```
$ cargo run --bin noah -- --datadir ./test/noah1 onboard "1 btc"
$ cargo run --bin noah -- --datadir ./test/noah1 balance
```

Remember that all txs will just be in the mempool if you don't generate blocks
once a while...
 
```
$ bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass generatetoaddress 1 mtDDKi5mDjZqGzmbnfUnVQ8ZhCPMPVsApj
```

Then, let's send some money off-chain to a third wallet:

```
$ cargo run --bin noah -- --datadir ./test/noah3 create
$ cargo run --bin noah -- --datadir ./test/noah3 balance
# Should be empty..
$ NOAH3_PK=$(cargo run --bin noah -- --datadir ./test/noah3 get-vtxo-pubkey)
# For now every client has just a single pubkey.
$ echo "${NOAH3_PK}"
$ cargo run --bin noah -- --datadir ./test/noah1 send ${NOAH3_PK} "0.1 btc"
$ cargo run --bin noah -- --datadir ./test/noah3 balance
```

You will notice that there is a slight delay when sending, this is because the
client needs to wait for the start of the next round and currently no
out-of-round payments are supported. The round interval can be changed in the
arkd configuration.
