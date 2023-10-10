

GOVERSION=$(shell go version)
GOOS=$(shell go env GOOS)
GOARCH=$(shell go env GOARCH)


DUMPFRAME_DIR="./cmd/dumpframe/"
TRACING_AGENT_DIR="./cmd/srv6_tracing_agent/"

clean:
	cd ./pkg/ebpf/;rm *.tmp *.o.*;cd -


cleanall:
	$(MAKE) clean
	rm -rf $(DUMPFRAME_DIR)main
	rm -rf $(TRACING_AGENT_DIR)grpc_client
	rm -rf $(TRACING_AGENT_DIR)main


proto:
	protoc --go_out=. --go-grpc_out=. nfagent/api/packet_collector.proto


build:
	go mod tidy
	go generate ./...
	cd $(DUMPFRAME_DIR);go build main.go;chmod +x main;cd -
	cd $(TRACING_AGENT_DIR);go build grpc_client.go;chmod +x grpc_client;cd -
	cd $(TRACING_AGENT_DIR);go build main.go;chmod +x main;cd -
	$(MAKE) clean


install:
	git submodule init
	git submodule sync
	git submodule update
	sudo mkdir -p /var/log/srv6_ptf/
	sudo cp cmd/srv6_tracing_agent/main /usr/local/bin/srv6_ebpfagent
	sudo chmod +x /usr/local/bin/srv6_ebpfagent

