package main

import (
	"flag"
	"github.com/shu1r0/srv6ptf_ebpfagent/internal/config"
	"github.com/shu1r0/srv6ptf_ebpfagent/internal/log_utils"
	"github.com/shu1r0/srv6ptf_ebpfagent/pkg/ebpf"
	"os"
	"os/signal"
	"strings"

	"github.com/shu1r0/srv6ptf_ebpfagent/pkg/agent"
	log "github.com/sirupsen/logrus"
)

func main() {
	var (
		ip       = flag.String("ip", "[::]", "server ip address")
		port     = flag.Int("port", 31000, "server port")
		conf     = flag.String("conf-file", "", "conf file")
		logf     = flag.String("log-file", "/var/log/srv6_ptf/collector-agent.log", "log file")
		logl     = flag.String("log-level", "info", "log level (panic, fatal, error, warn, info, debug, trace)")
		inifaces = flag.String("in-ifaces", "", "")
		eifaces  = flag.String("e-ifaces", "", "")
		noAttach = flag.Bool("no-tc-xdp", false, "")
	)
	flag.Parse()

	if f := log_utils.SetupLogger(*logl, *logf); f != nil {
		defer func() {
			if err := f.Close(); err != nil {
				log.Panic(err)
			}
		}()
	}

	var endInsertId []ebpf.Seg6LocalEndInsertIdRoute = nil
	if *conf != "" {
		routeConf, err := config.ParseConfFile(*conf)
		if err != nil {
			log.Panic(err)
		}
		endInsertId = routeConf.Routes.Add.EndInsertId
	}

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

	if endInsertId != nil {
		ag.Dp.EndIIDRoutesConfig = endInsertId
	}

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)

	go ag.Start()

	<-quit
	ag.Stop()
}
