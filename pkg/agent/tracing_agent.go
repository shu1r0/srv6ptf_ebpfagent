package agent

import (
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"sync"

	"github.com/shu1r0/srv6ptf_ebpfagent/pkg/api"
	"github.com/shu1r0/srv6ptf_ebpfagent/pkg/utils"

	"github.com/shu1r0/srv6ptf_ebpfagent/pkg/ebpf"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

type TracingAgent struct {
	api.UnimplementedPacketCollectServiceServer
	Server        *grpc.Server
	Ip            string
	Port          int
	InfoChan      chan ebpf.PacketInfo
	Dp            *ebpf.TracingDataPlane
	NodeId        uint32
	diffWallMono  float64
	AttachOptions *ebpf.AttachAllOptions
}

func NewTracingAgent(ip string, port int) (*TracingAgent, error) {
	server := grpc.NewServer()
	dp, err := ebpf.NewTracingDataPlane(nil)
	if err != nil {
		return nil, fmt.Errorf("Tracking Data Plane Create: %s", err)
	}

	return &TracingAgent{Server: server, Ip: ip, Port: port, Dp: dp, diffWallMono: utils.GetDiffWallMono(), AttachOptions: nil}, nil
}

func (cp *TracingAgent) Start() {
	log.Info("Start gRPC Server.")
	lis, err := net.Listen(("tcp"), fmt.Sprintf("%s:%d", cp.Ip, cp.Port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	api.RegisterPacketCollectServiceServer(cp.Server, cp)

	if err := cp.Server.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func (cp *TracingAgent) SetDp(nodeid uint32) {
	log.Info("Set eBPF program.")
	cp.NodeId = nodeid
	if err := cp.Dp.AttachAll(cp.AttachOptions); err != nil {
		log.Fatalf("Attach All Error: %s", err)
	}
	//TODO: NodeId size
	if err := cp.Dp.SetMapConf(uint64(cp.NodeId)); err != nil {
		log.Fatalf("Map Config Error: %s", err)
	}
	pktchan, err := cp.Dp.PacketInfoChan()
	if err != nil {
		log.Fatalf("Packet Info Error: %s", err)
	}
	cp.InfoChan = pktchan
}

func (cp *TracingAgent) Stop() {
	log.Info("Stop gRPC Server.")
	cp.Server.GracefulStop()
	if err := cp.Dp.Close(); err != nil {
		log.Fatalf("Dataplane Close Error: %s", err)
	}
	cp.Dp.DettachAll()
}

func (cp *TracingAgent) SetPoll(context.Context, *api.PollSettingRequest) (*api.PollSettingReply, error) {
	// 仮実装
	log.Info("Called SetPoll")
	rep := &api.PollSettingReply{}
	return rep, nil
}

func (cp *TracingAgent) GetPacketInfo(context.Context, *api.PacketInfoRequest) (*api.PacketInfoReply, error) {
	// 仮実装
	log.Info("Called GetPacketInfo")
	rep := &api.PacketInfoReply{}
	return rep, nil
}

func (cp *TracingAgent) GetPacketInfoStream(req *api.PacketInfoStreamRequest, stream api.PacketCollectService_GetPacketInfoStreamServer) error {
	log.Info("Called GetPacketInfoStream")
	var wg sync.WaitGroup
	wg.Add(1)
	// TODO: couter_length
	cp.SetDp(req.NodeId)

	go func() {
		for {
			pktinfo := <-cp.InfoChan

			log.Traceln("********** getPacket **********")
			log.Tracef("Packet : %s\n", hex.EncodeToString(pktinfo.Pkt))
			log.Tracef("Packet ID : %d\n", pktinfo.PktId)
			log.Tracef("Timestamp (mono): %b\n", pktinfo.MonotoricTimestamp)
			log.Tracef("Hook: %d\n", pktinfo.Hookpoint)

			if err := stream.Send(cp.pkti2msg(&pktinfo)); err != nil {
				wg.Done()
				log.Errorf("PacketInfor Stream: %s\n", err)
				break
			}
		}
	}()
	wg.Wait()
	return nil
}

func (cp *TracingAgent) pkti2msg(pkt *ebpf.PacketInfo) *api.PacketInfo {

	msg := &api.PacketInfo{
		NodeId:      cp.NodeId,
		Timestamp:   float64(pkt.MonotoricTimestamp)*math.Pow(10, -10) + cp.diffWallMono,
		PktidExthdr: api.PktIdExtHdr_EXTHDR_ROUTING,
	}
	if pkt.Hookpoint == 1 || pkt.Hookpoint == 2 {
		msg.Metadata = &api.PacketInfo_EbpfInfo{EbpfInfo: &api.EBPFInfo{Hookpoint: api.EBPFHook_XDP}}
		msg.PacketProtocol = api.PacketProtocol_PROTOCOL_ETH
	} else if pkt.Hookpoint == 3 || pkt.Hookpoint == 4 {
		msg.Metadata = &api.PacketInfo_EbpfInfo{EbpfInfo: &api.EBPFInfo{Hookpoint: api.EBPFHook_TC_EGRESS}}
		msg.PacketProtocol = api.PacketProtocol_PROTOCOL_ETH
	} else if pkt.Hookpoint == 5 || pkt.Hookpoint == 6 {
		msg.Metadata = &api.PacketInfo_EbpfInfo{EbpfInfo: &api.EBPFInfo{Hookpoint: api.EBPFHook_LWT_IN}}
		msg.PacketProtocol = api.PacketProtocol_PROTOCOL_IPV6
	} else if pkt.Hookpoint == 7 || pkt.Hookpoint == 8 {
		msg.Metadata = &api.PacketInfo_EbpfInfo{EbpfInfo: &api.EBPFInfo{Hookpoint: api.EBPFHook_LWT_XMIT}}
		msg.PacketProtocol = api.PacketProtocol_PROTOCOL_IPV6
	} else if pkt.Hookpoint == 9 || pkt.Hookpoint == 10 {
		msg.Metadata = &api.PacketInfo_EbpfInfo{EbpfInfo: &api.EBPFInfo{Hookpoint: api.EBPFHook_LWT_OUT}}
		msg.PacketProtocol = api.PacketProtocol_PROTOCOL_IPV6
	} else if pkt.Hookpoint == 11 || pkt.Hookpoint == 12 {
		msg.Metadata = &api.PacketInfo_EbpfInfo{EbpfInfo: &api.EBPFInfo{Hookpoint: api.EBPFHook_LWT_SEG6LOCAL}}
		msg.PacketProtocol = api.PacketProtocol_PROTOCOL_IPV6
	}
	if pkt.Hookpoint%2 == 0 { // push id
		msg.Data = &api.PacketInfo_Packet{Packet: pkt.Pkt}
	} else { // get id
		msg.Data = &api.PacketInfo_PacketId{PacketId: uint64(pkt.PktId)}
	}

	log.Tracef("PcketInfo gRPC msg: %s", msg.String())
	return msg
}
