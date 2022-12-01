all: build

build: 
	go generate ./...
	cd examples/dumpframe/;go build main.go;cd -

proto:
	protoc --go_out=. --go-grpc_out=. api/packet_collector.proto
