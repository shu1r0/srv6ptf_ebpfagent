all: build

build: 
	go generate ./...
	cd examples/dumpframe/;go build main.go;cd -
	cd cmd/srv6_tracing_agent/;go build main.go;cd -
	cd ./pkg/ebpf/;rm *.tmp *.o.*;cd -
	sudo cp cmd/srv6_tracing_agent/main /usr/local/bin/srv6_ebpfagent

proto:
	protoc --go_out=. --go-grpc_out=. api/packet_collector.proto
