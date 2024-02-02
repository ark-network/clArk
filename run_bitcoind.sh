#!/bin/sh


datadir=./test/bitcoindatadir

bitcoind -regtest -datadir=${datadir} -rpcuser=user -rpcpassword=pass -server -txindex
