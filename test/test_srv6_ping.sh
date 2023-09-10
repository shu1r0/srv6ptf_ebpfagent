#!/usr/bin/env bash

#if [[ $(id -u) -ne 0 ]] ; then echo "Please run with sudo" ; exit 1 ; fi

source $HOME/.bashrc

sudo ./netns_network_examples/simple/2hosts.sh -d

sudo ./setup.sh

cd ..
make install
cd -

# set -e


##### Test TC/XDP eBPF Hook #####
# -- Start network
sudo ./netns_network_examples/simple/2hosts.sh -c
ip netns exec ns2 ip -6 route add default dev ns2_veth2 via  2001:db8:20::1

# start agent
sudo ip netns exec ns2 sudo ../cmd/srv6_tracing_agent/main -log-level trace -log-file ./test_log.log &
# start client
sudo ip netns exec ns2 ../cmd/srv6_tracing_agent/grpc_client &
# run test
sudo ip netns exec ns1 python3 -m unittest ./test_brackbox.py

sudo ./netns_network_examples/simple/2hosts.sh -d
# -- Stop network


##### Test EndBPF Hook #####
# -- Start network
sudo ./netns_network_examples/simple/2hosts.sh -c
ip netns exec ns2 ip -6 route add default dev ns2_veth2 via  2001:db8:20::1

sudo ip netns exec ns1 ip -6 route add 2001:db8:10::3/128 dev ns1_veth1 via  2001:db8:10::2
sudo ip netns exec ns1 ip -6 route add 2001:db8:10::4/128 dev ns1_veth1 via  2001:db8:10::2
sudo ip netns exec ns2 sudo ping -c 3 2001:db8:20::1

# start agent
sudo ip netns exec ns2 sudo ../cmd/srv6_tracing_agent/main -no-tc-xdp -conf-file ./test_routes.yaml -log-level trace -log-file ./test_log.log &
# sudo ip netns exec ns2 tcpdump -i ns2_veth2 -w ns2_veth2.pcap &
# sudo ip netns exec ns2 tcpdump -i lo -w lo.pcap &
# sudo ip netns exec ns2 tcpdump -i ns2_veth1 -w ns2_veth1.pcap &

# start client
sudo ip netns exec ns2 ../cmd/srv6_tracing_agent/grpc_client &
sleep 5
# run test
sudo ip netns exec ns1 python3 -m unittest ./test_end_bpf.py

sleep 1
sudo ip netns exec ns2 ip -6 route show
sudo ip netns exec ns2 ip -s link show
# print bpf trace
# sudo cat /sys/kernel/tracing/trace

sudo ./netns_network_examples/simple/2hosts.sh -d
# -- Stop network


##### Test Dump frame test #####
# -- Start network
sudo ./netns_network_examples/simple/2hosts.sh -c
ip netns exec ns2 ip -6 route add default dev ns2_veth2 via  2001:db8:20::1

# start agent
sudo ip netns exec ns2 sudo ../cmd/dumpframe/main -log-level trace -log-file ./test_log.log &
# run test
sudo ip netns exec ns1 python3 -m unittest ./test_brackbox.py

sudo ./netns_network_examples/simple/2hosts.sh -d
# -- Stop network

sudo rm -rf ./srv6_ping/
