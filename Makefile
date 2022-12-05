all: build

build: 
	go generate ./...
	cd examples/dumpframe/;go build main.go;cd -
	cd ./pkg/ebpf/;rm *.tmp *.o.*;cd -

proto:
	protoc --go_out=. --go-grpc_out=. api/packet_collector.proto
