package main

import (
	"flag"
	"os"
	"os/signal"
	"strings"

	"github.com/shu1r0/srv6ptf_ebpfagent/internal/config"
	"github.com/shu1r0/srv6ptf_ebpfagent/internal/log_utils"
	"github.com/shu1r0/srv6ptf_ebpfagent/pkg/ebpf"

	"github.com/shu1r0/srv6ptf_ebpfagent/pkg/agent"
	log "github.com/sirupsen/logrus"
)

func main() {
	var (
		ip   = flag.String("ip", "[::]", "server ip address")
		port = flag.Int("port", 31000, "server port")

		conf = flag.String("conf-file", "", "Configuration YAML file")
		logf = flag.String("log-file", "/var/log/srv6_ptf/collector-agent.log", "log file")
		logl = flag.String("log-level", "info", "log level (panic, fatal, error, warn, info, debug, trace)")

		inifaces = flag.String("in-ifaces", "", "Interfaces for XDP (default all interfaces)")
		eifaces  = flag.String("e-ifaces", "", "Interfaces for TC Egress (default all interfaces)")

		noAttachXDP      = flag.Bool("no-xdp", false, "Not attached to XDP")
		noAttachTCEgress = flag.Bool("no-tc-egress", false, "Not attached to TC")
		xdpReadOnly      = flag.Bool("xdp-read-only", false, "")
		tcEgressReadOnly = flag.Bool("tc-egress-read-only", false, "")
		agentMode        = flag.String("mode", "packetidmode", "mode to collect packet (packetmode or packetidmode)")
	)
	flag.Parse()

	if f := log_utils.SetupLogger(*logl, *logf); f != nil {
		defer func() {
			if err := f.Close(); err != nil {
				log.Panic(err)
			}
		}()
	}

	// routes
	var endInsertId []ebpf.LWTAttachRoute = nil
	var xmitReadId []ebpf.LWTAttachRoute = nil
	var inReadId []ebpf.LWTAttachRoute = nil
	var outReadId []ebpf.LWTAttachRoute = nil

	// setup route config
	if *conf != "" {
		routeConf, err := config.ParseConfFile(*conf)
		if err != nil {
			log.Panic(err)
		}
		endInsertId = routeConf.Routes.Add.EndInsertId
		xmitReadId = routeConf.Routes.Add.XmitReadId
		inReadId = routeConf.Routes.Add.InReadId
		outReadId = routeConf.Routes.Add.OutReadId
	}

	// ebpf interfaces
	attachOpt, err := ebpf.NewAttachAllOptions()
	if err != nil {
		log.Fatalf("New Attach All Options Error: {}", err)
	}
	if *inifaces != "" {
		attachOpt.InIfaces = strings.Split(*inifaces, ",")
	}
	if *eifaces != "" {
		attachOpt.EIfaces = strings.Split(*eifaces, ",")
	}
	attachOpt.NoXDP = *noAttachXDP
	attachOpt.NoTCEgress = *noAttachTCEgress

	// flags
	flags := &ebpf.TracerFlags{true, true}
	if *xdpReadOnly {
		flags.EnablePushPktIdXDP = false
	}
	if *tcEgressReadOnly {
		flags.EnablePushPktIdTCEgress = false
	}

	ag, err := agent.NewTracingAgent(*ip, *port, flags)
	if err != nil {
		log.Fatalf("New Agent Error: {}", err)
	}
	ag.AttachOptions = attachOpt

	// route config
	if endInsertId != nil {
		ag.Dp.EndIIDRoutesConfig = endInsertId
	}
	if xmitReadId != nil {
		ag.Dp.XmitReadIdRoutesConfig = xmitReadId
	}
	if inReadId != nil {
		ag.Dp.InReadIdRoutesConfig = inReadId
	}
	if outReadId != nil {
		ag.Dp.OutReadIdRoutesConfig = outReadId
	}

	// set Agent mode
	ag.Mode = agent.ParseString(*agentMode)

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)

	// start agent
	go ag.Start()

	<-quit
	ag.Stop()
}
