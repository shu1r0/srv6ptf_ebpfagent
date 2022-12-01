package api

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/shu1r0/srv6tracking_ebpfagent/pkg/ebpf"
	"google.golang.org/grpc"
)

type TelemetryControlPlane struct {
	UnimplementedPacketCollectServiceServer
	Server   *grpc.Server
	Ip       string
	Port     int
	InfoChan chan ebpf.PacketInfo
}

func NewTelemetryControlPlane(ip string, port int) *TelemetryControlPlane {
	server := grpc.NewServer()
	c := make(chan ebpf.PacketInfo)
	return &TelemetryControlPlane{Server: server, Ip: ip, Port: port, InfoChan: c}
}

func (cp *TelemetryControlPlane) Start() {
	lis, err := net.Listen(("tcp"), fmt.Sprintf("localhost:%d", cp.Port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	RegisterPacketCollectServiceServer(cp.Server, cp)
	cp.Server.Serve(lis)
}

func (cp *TelemetryControlPlane) Stop() {
	cp.Server.Stop()
}

func (cp *TelemetryControlPlane) SetPoll(context.Context, *PollSettingRequest) (*PollSettingReply, error) {
	// 仮実装
	rep := &PollSettingReply{}
	return rep, nil
}

func (cp *TelemetryControlPlane) GetPacketInfo(context.Context, *PacketInfoRequest) (*PacketInfoReply, error) {
	// 仮実装
	rep := &PacketInfoReply{}
	return rep, nil
}

func (cp *TelemetryControlPlane) GetPacketInfoStream(req *PacketInfoStreamRequest, stream PacketCollectService_GetPacketInfoStreamServer) error {
	for {
		// ここで，結果を返すような実装を，，，
	}
	return nil
}
