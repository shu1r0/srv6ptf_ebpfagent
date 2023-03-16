package main

import (
	"encoding/hex"
	"flag"
	"github.com/shu1r0/srv6tracing_ebpfagent/internal/log_utils"
	"os"
	"os/signal"

	"github.com/shu1r0/srv6tracing_ebpfagent/pkg/ebpf"
	log "github.com/sirupsen/logrus"
)

func main() {
	var (
		logf = flag.String("log-file", "", "log file")
		logl = flag.String("log-level", "info", "log level (panic, fatal, error, warn, info, debug, trace)")
	)
	flag.Parse()

	log_utils.SetupLogger(*logl, *logf)

	dp, err := ebpf.NewTracingDataPlane(nil)
	if err != nil {
		log.Panicf("Telemetry DP Error: %s", err)
	}
	defer dp.Close()

	if err := dp.AttachAll(); err != nil {
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
			log.Printf("Packet : %s\n", hex.EncodeToString(pktinfo.Pkt[24:]))
			log.Printf("Packet ID : %b\n", pktinfo.PktId)
			log.Printf("Timestamp (mono): %d\n", pktinfo.MonotoricTimestamp)
			log.Printf("Hook: %d\n", pktinfo.Hookpoint)
			log.Println(hex.Dump(pktinfo.Pkt[24:]))
			//pkt := gopacket.NewPacket(pktinfo.Pkt[24:], layers.LayerTypeEthernet, gopacket.Default)
			//fmt.Println(pkt)
		}
	}()
	<-quit
}
