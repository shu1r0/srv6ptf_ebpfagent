#!/usr/bin/env bash

#if [[ $(id -u) -ne 0 ]] ; then echo "Please run with sudo" ; exit 1 ; fi

source $HOME/.bashrc

sudo ./netns_network_examples/simple/2hosts.sh -d

sudo ./setup.sh

cd ..
make install
cd -

set -e

sudo ./netns_network_examples/simple/2hosts.sh -c
# start agent
sudo ip netns exec ns2 sudo ../cmd/srv6_tracing_agent/main -log-level trace &
# start client
sudo ip netns exec ns2 ../cmd/srv6_tracing_agent/grpc_client &
# run test
sudo ip netns exec ns1 python3 -m unittest discover ./
sudo ./netns_network_examples/simple/2hosts.sh -d
sudo rm -rf ./srv6_ping/