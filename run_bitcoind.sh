#!/bin/sh



datadir=./test/bitcoindatadir
# rm -r $datadir
# mkdir -p $datadir

/home/steven/code/bitcoin/src/bitcoind -regtest -datadir=${datadir} -rpcuser=user -rpcpassword=pass -server -txindex 
