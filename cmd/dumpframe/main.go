package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/shu1r0/srv6ptf_ebpfagent/internal/log_utils"

	"github.com/shu1r0/srv6ptf_ebpfagent/pkg/ebpf"
	log "github.com/sirupsen/logrus"
)

func main() {
	var (
		logf = flag.String("log-file", "", "log file")
		logl = flag.String("log-level", "info", "log level (panic, fatal, error, warn, info, debug, trace)")
	)
	flag.Parse()

	if f := log_utils.SetupLogger(*logl, *logf); f != nil {
		defer func() {
			if err := f.Close(); err != nil {
				log.Panic(err)
			}
		}()
	}

	dp, err := ebpf.NewTracingDataPlane(nil, nil)
	if err != nil {
		log.Panicf("Telemetry DP Error: %s", err)
	}
	defer dp.Close()

	if err := dp.AttachAll(nil); err != nil {
		log.Panicf("Attach All Error: %s", err)
	}
	defer dp.DettachAll()

	if err := dp.SetMapConf(1); err != nil {
		log.Panicf("Map Config Error: %s", err)
	}

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)

	pktchan, err := dp.PacketInfoChan()
	if err != nil {
		log.Panicf("Packet Info Error: %s", err)
	}
	go func() {
		for {
			pktinfo := <-pktchan
			log.Println("********** getPacket **********")
			log.Printf("Get Data: %s\n", hex.EncodeToString(pktinfo.Pkt))
			log.Printf("Packet : %s\n", hex.EncodeToString(pktinfo.Pkt))
			log.Printf("Packet ID : %x\n", pktinfo.PktId)
			log.Printf("Timestamp (mono): %d\n", pktinfo.MonotoricTimestamp)
			log.Printf("Hook: %d\n", pktinfo.Hookpoint)
			log.Println(hex.Dump(pktinfo.Pkt))
			pkt := gopacket.NewPacket(pktinfo.Pkt, layers.LayerTypeEthernet, gopacket.Default)
			fmt.Println(pkt)
		}
	}()
	<-quit
}
