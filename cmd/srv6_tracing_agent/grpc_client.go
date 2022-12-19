package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/shu1r0/srv6tracing_ebpfagent/pkg/api"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"os"
	"time"
)

func GetPacketInfo(ip string, port int) {
	addr := fmt.Sprintf("%s:%d", ip, port)
	log.Info(addr)
	conn, err := grpc.Dial(addr, grpc.WithTimeout(4*time.Second), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		log.Panic("Connection failed.")
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
	defer cancel()

	client := api.NewPacketCollectServiceClient(conn)
	req := &api.PacketInfoStreamRequest{
		NodeId: 1,
	}
	log.Info("Connect!")

	stream, err := client.GetPacketInfoStream(ctx, req)
	if err != nil {
		log.Panic("Request failed")
	}
	log.Info("Sent Request")

	for {
		res, err := stream.Recv()
		if err != nil {
			log.Fatalf("Stream Recv Error: %s", err)
		}
		log.Println(res.GetPacket())
		return

	}
}

func main() {
	var (
		ip   = flag.String("ip", "[::]", "server ip address")
		port = flag.Int("port", 31000, "server port")
	)
	flag.Parse()

	log.SetOutput(os.Stdout)
	log.Info("Get Packet Request")
	GetPacketInfo(*ip, *port)
}
