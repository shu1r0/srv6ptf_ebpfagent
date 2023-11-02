#!/usr/bin/env bash

#if [[ $(id -u) -ne 0 ]] ; then echo "Please run with sudo" ; exit 1 ; fi

source $HOME/.bashrc

sudo ./netns_network_examples/simple/2hosts_1router.sh -d

sudo ./setup.sh

cd ..
make install
cd -

# set -e


##### Test TC/XDP eBPF Hook #####
# -- Start network
sudo ./netns_network_examples/simple/2hosts_1router.sh -c
# start agent
sudo ip netns exec r1 sudo ../cmd/srv6_tracing_agent/main -log-level trace -log-file ./test_log.log &

# run test
sudo ip netns exec h1 python3 -m unittest ./test_brackbox.py

sudo ./netns_network_examples/simple/2hosts_1router.sh -d
# -- Stop network


##### Test EndBPF Hook #####
# -- Start network
sudo ./netns_network_examples/simple/2hosts_1router.sh -c
sudo ip netns exec h2 sudo ping -c 3 2001:db8:20::1

# start agent
sudo ip netns exec r1 sudo ../cmd/srv6_tracing_agent/main -no-tc-xdp -conf-file ./test_routes.yaml -log-level trace -log-file ./test_log.log &
# sudo ip netns exec h2 tcpdump -i h2_r1 -w h2_r1.pcap &
# sudo ip netns exec h2 tcpdump -i lo -w lo.pcap &
# sudo ip netns exec h2 tcpdump -i h2_veth1 -w h2_veth1.pcap &

# start client
sudo ip netns exec h2 ../cmd/srv6_tracing_agent/grpc_client &
sleep 5
# run test
sudo ip netns exec h1 python3 -m unittest ./test_end_bpf.py

sleep 1
sudo ip netns exec h2 ip -6 route show
sudo ip netns exec h2 ip -s link show
# print bpf trace
# sudo cat /sys/kernel/tracing/trace

sudo ./netns_network_examples/simple/2hosts_1router.sh -d
# -- Stop network


##### Test Dump frame test #####
# # -- Start network
# sudo ./netns_network_examples/simple/2hosts_1router.sh -c
# ip netns exec h2 ip -6 route add default dev h2_r1 via  2001:db8:20::1

# # start agent
# sudo ip netns exec h2 sudo ../cmd/dumpframe/main -log-level trace -log-file ./test_log.log &
# # run test
# sudo ip netns exec h1 python3 -m unittest ./test_brackbox.py

# sudo ./netns_network_examples/simple/2hosts_1router.sh -d
# # -- Stop network

sudo rm -rf ./srv6_ping/
