#!/bin/sh



datadir=./test/bitcoindatadir
rm -r $datadir
mkdir -p $datadir

bitcoind -regtest -datadir=./test/bitcoindatadir -rpcuser=user -rpcpassword=pass -server
