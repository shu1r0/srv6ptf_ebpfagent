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

		noAttach  = flag.Bool("no-tc-xdp", false, "Not attached to XDP and TC")
		agentMode = flag.String("mode", "packetmode", "mode to collect packet (packet or packet_id)")
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
	var endInsertId []ebpf.Seg6LocalEndInsertIdRoute = nil
	var xmitReadId []ebpf.LWTReadIdRoute = nil
	var inReadId []ebpf.LWTReadIdRoute = nil
	var outReadId []ebpf.LWTReadIdRoute = nil

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
	var attachOpt *ebpf.AttachAllOptions = nil
	if *inifaces != "" || *eifaces != "" {
		attachOpt = &ebpf.AttachAllOptions{
			InIfaces: strings.Split(*inifaces, ","),
			EIfaces:  strings.Split(*eifaces, ","),
		}
	}
	if *noAttach {
		attachOpt = &ebpf.AttachAllOptions{InIfaces: []string{}, EIfaces: []string{}}
	}

	ag, err := agent.NewTracingAgent(*ip, *port)
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
