#!/usr/bin/env bash

#if [[ $(id -u) -ne 0 ]] ; then echo "Please run with sudo" ; exit 1 ; fi

source $HOME/.bashrc

sudo ./netns_network_examples/simple/2hosts_1router.sh -d

sudo ./setup.sh

cd ..
make build
make install
cd -

set -e


##### Test TC/XDP eBPF Hook #####
# -- Start network
sudo ./netns_network_examples/simple/2hosts_1router.sh -c

# route for TC Egress Hook
sudo ip netns exec h2 ip -6 addr add 2001:db8:20::100/48 dev h2_r1
sudo ip netns exec r1 ip -6 route add 2001:db8:20::100/128 encap seg6 mode inline segs 2001:db8:20::2 dev r1_h1

# start agent
sudo ip netns exec r1 sudo ../cmd/srv6_tracing_agent/main -log-level trace -log-file ./test_log.log &
sleep 3

# test ping
sudo ip netns exec h1 sudo ping -c 3 2001:db8:20::2

# run test
sudo ip netns exec h1 python3 -m unittest ./test_brackbox.py

sudo ./netns_network_examples/simple/2hosts_1router.sh -d
# -- Stop network


##### Test EndBPF Hook #####
# -- Start network
sudo ./netns_network_examples/simple/2hosts_1router.sh -c
# for readid
sudo ip netns exec h2 ip -6 addr add 2001:db8:20::3/48 dev h2_r1
sudo ip netns exec h2 ip -6 addr add 2001:db8:20::4/48 dev h2_r1
sudo ip netns exec h2 ip -6 addr add 2001:db8:20::5/48 dev h2_r1
# for encap => endbpf
sudo ip netns exec h2 ip -6 addr add 2001:db8:20::100/48 dev h2_r1
sudo ip netns exec r1 ip -6 route add 2001:db8:20::100/128 encap seg6 mode encap segs 2001:db8:30::3,2001:db8:20::2 dev r1_h1

# start agent
sudo ip netns exec r1 sudo ../cmd/srv6_tracing_agent/main -xdp-read-only -no-tc-egress -conf-file ./test_routes.yaml -log-level trace -log-file ./test_log.log &
sleep 3

# sudo ip netns exec r1 tcpdump -i r1_h1 -w r1_h1.pcap &

# test ping
sudo ip netns exec h1 sudo ping -c 3 2001:db8:20::2
sudo ip netns exec h1 sudo ping -c 3 2001:db8:20::3
# sudo ip netns exec h1 sudo ping -c 3 2001:db8:20::100

# run test
sudo ip netns exec h1 python3 -m unittest ./test_end_bpf.py

sleep 1
sudo ip netns exec r1 ip -6 route show
sudo ip netns exec r1 ip -s link show
# print bpf trace
# sudo cat /sys/kernel/tracing/trace

sudo ./netns_network_examples/simple/2hosts_1router.sh -d
# -- Stop network


sudo rm -rf ./srv6_ping/
