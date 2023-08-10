#!/usr/bin/env bash

#if [[ $(id -u) -ne 0 ]] ; then echo "Please run with sudo" ; exit 1 ; fi

source $HOME/.bashrc

sudo ./netns_network_examples/simple/2hosts.sh -d

sudo ./setup.sh

cd ..
make install
cd -

# set -e

## -- Start network
#sudo ./netns_network_examples/simple/2hosts.sh -c
#
## start agent
#sudo ip netns exec ns2 sudo ../cmd/srv6_tracing_agent/main -log-level trace &
## start client
#sudo ip netns exec ns2 ../cmd/srv6_tracing_agent/grpc_client &
## run test
#sudo ip netns exec ns1 python3 -m unittest discover ./
#
#sudo ./netns_network_examples/simple/2hosts.sh -d
## -- Stop network

# -- Start network
sudo ./netns_network_examples/simple/2hosts.sh -c

# start agent
sudo ip netns exec ns2 sudo ../cmd/srv6_tracing_agent/main -no-tc-xdp -conf-file ./test_routes.yaml -log-level trace &
sudo ip netns exec ns2 tcpdump -i ns2_veth2 -w ns2_veth2.pcap &
# start client
sudo ip netns exec ns2 ../cmd/srv6_tracing_agent/grpc_client &
sleep 5
sudo ip netns exec ns2 ip -6 route show
# run test
sudo ip netns exec ns1 python3 -m unittest discover ./

sleep 1
sudo cat /sys/kernel/tracing/trace

sudo ./netns_network_examples/simple/2hosts.sh -d
# -- Stop network

# # -- Start network
# sudo ./netns_network_examples/simple/2hosts.sh -c

# # start agent
# sudo ip netns exec ns2 sudo ../cmd/dumpframe/main -log-level trace &
# # run test
# sudo ip netns exec ns1 python3 -m unittest discover ./

# # print bpf trace
# # sudo cat /sys/kernel/tracing/trace
# sudo ./netns_network_examples/simple/2hosts.sh -d
# # -- Stop network

sudo rm -rf ./srv6_ping/