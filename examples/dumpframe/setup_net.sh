#!/bin/bash


git clone https://github.com/shu1r0/srv6ptf_nfagent.git
sudo pip3 install protobuf~=3.20.1
sudo pip3 install grpcio
sudo pip3 install grpcio-tools

sudo apt install -y libnetfilter-queue-dev
sudo pip3 install NetfilterQueue

