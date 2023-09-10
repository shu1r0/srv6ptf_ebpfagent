#!/usr/bin/env bash

sudo apt install -y libnetfilter-queue-dev

git clone https://github.com/shu1r0/srv6_ping.git
cd srv6_ping
sudo ./install.sh
cd -

cd ../nfagent
sudo ./install.sh
cd -
