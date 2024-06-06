rust-ark
========

An implementation of the Ark second-layer payment protocol for Bitcoin.

This repository comprises an ASP server, `arkd`, a client wallet, `noah`, and
a library that contains all the primitives used for these implementations.




# Demo

You can play around with the tools as follows:


First you have to setup a `regtest bitcoind` node, there is a script provided for
that. If you want to run your own node, keep in mind that for now, we need it
to have the txindex and server options enabled.

```
$ ./run_bitcoind.sh
```

Edit the `bitcoin.conf` file in `test/bitcoindatadir` directory created by the script to include your RPC Auth credentials:

```
rpcauth=<userpw>
```

The field `<userpw>` comes in the format: `<USERNAME>:<SALT>$<HASH>`. 
RPC clients connect using `rpcuser=<USERNAME>` and `rpcpassword=<PASSWORD>` arguments. 
You can generate this value at [here](https://jlopp.github.io/bitcoin-core-rpc-auth-generator/). 
This option can be specified multiple times.

Run the script again, then take note of these lines when starting your node:

```
Binding RPC on address <DOMAIN> port <PORT>
Using random cookie authentication.
Generated RPC authentication cookie <BITCOIND COOKIE>
```

Your `<BITCOIND>` URL will be `<DOMAIN>:<PORT>` and your `<BITCOIND COOKIE>` will be the location where the cookie file was generated.

You can interact with the node using `bitcoin-cli` as follows:

```
$ bitcoin-cli -regtest -rpcuser=<USERNAME> -rpcpassword=<PASSWORD> getnetworkinfo
```

You can create an `arkd` server by running the following command:

```
$ cargo run --bin arkd create --datadir test/arkd --bitcoind-url <BITCOIND> --bitcoind-cookie <BITCOIND COOKIE>
```

This will create a new `arkd` server in the `test/` directory. You also can change the parameters as needed using the configuration file that gets created at `test/config.json`.

You can then start the server with:

```
$ cargo run --bin arkd start --datadir test/arkd
```

For `arkd` to work properly, you should fund it with some liquidity, this
can be done by sending some money to the address that is printed out when arkd
is started. You can send money there as follows:

```
$ bitcoin-cli -regtest -rpcuser=<USERNAME> -rpcpassword=<PASSWORD> generatetoaddress 1 <asp-addr>
# Then give it 100 confirmations because it's a coinbase output.
$ bitcoin-cli -regtest -rpcuser=<USERNAME> -rpcpassword=<PASSWORD> generatetoaddress 100 mtDDKi5mDjZqGzmbnfUnVQ8ZhCPMPVsApj
```

Next, you can start some clients. To create a client, use the following command:

```
$ cargo run --bin noah -- --datadir ./test/noah1 create --regtest --asp http://<ARKD-URL> --bitcoind <BITCOIND> --bitcoind-cookie <BITCOIND COOKIE>
$ cargo run --bin noah -- --datadir ./test/noah2 create ... same as above 
```

These will create individual wallets and print an on-chain address you can use
to **fund them the same way as you did for the ASP above**. 

Note that clients can receive off-chain Ark transactions without having any on-chain balance, 
but a little bit of on-chain money is needed to perform unilateral exits.

To use the on-chain wallets, there are a few commands available:

```
# First lets fund one wallet
$ NOAH1_ADDR=$(cargo run --bin noah -- --datadir ./test/noah2 get-address)
$ bitcoin-cli -regtest -rpcuser=<USERNAME> -rpcpassword=<PASSWORD> generatetoaddress 1 $NOAH1_ADDR
# Again give it 100 confirmations because it's a coinbase output.
$ bitcoin-cli -regtest -rpcuser=<USERNAME> -rpcpassword=<PASSWORD> generatetoaddress 100 mtDDKi5mDjZqGzmbnfUnVQ8ZhCPMPVsApj
# Then send some money to the other wallet
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
$ bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass generatetoaddress 10 mtDDKi5mDjZqGzmbnfUnVQ8ZhCPMPVsApj
```

Then, let's send some money off-chain to a third wallet:

```
$ cargo run --bin noah -- --datadir ./test/noah3 create ... with same flags as before
$ cargo run --bin noah -- --datadir ./test/noah3 balance
# Should be empty..
$ NOAH3_PK=$(cargo run --bin noah -- --datadir ./test/noah3 get-vtxo-pubkey)
# For now every client has just a single pubkey.
$ echo "${NOAH3_PK}"
$ cargo run --bin noah -- --datadir ./test/noah1 send-round ${NOAH3_PK} "0.1 btc"
$ cargo run --bin noah -- --datadir ./test/noah3 balance
```

You will notice that there is a slight delay when sending, this is because the
client needs to wait for the start of the next round and currently no
out-of-round payments are supported. The round interval can be changed in the
`arkd` configuration.
