#!/bin/sh


datadir=./test/bitcoindatadir
mkdir -p ${datadir}
conf_file=${datadir}/bitcoin.conf

# Check if bitcoin.conf exists, if not, create it
if [ ! -f "$conf_file" ]; then
    touch "$conf_file"
fi

bitcoind -regtest -datadir=${datadir} -server -txindex
