#!/bin/sh


datadir=./test/bitcoindatadir
mkdir -p ${datadir}

bitcoind -regtest -datadir=${datadir} -server -txindex
