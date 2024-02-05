#!/bin/sh


datadir=./test/bitcoindatadir
mkdir -p ${datadir}

bitcoind -regtest -datadir=${datadir} -rpcuser=user -rpcpassword=pass -server -txindex
