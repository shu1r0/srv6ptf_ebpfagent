package main

import (
	"flag"
	"github.com/shu1r0/srv6tracing_ebpfagent/internal/log_utils"
	"os"
	"os/signal"

	"github.com/shu1r0/srv6tracing_ebpfagent/pkg/agent"
	log "github.com/sirupsen/logrus"
)

func main() {
	var (
		ip   = flag.String("ip", "[::]", "server ip address")
		port = flag.Int("port", 31000, "server port")
		logf = flag.String("log-file", "/var/log/srv6_ptf/collector-agent.log", "log file")
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

	ag, err := agent.NewTracingAgent(*ip, *port)
	if err != nil {
		log.Fatalf("New Agent Error: {}", err)
	}

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)

	go ag.Start()

	<-quit
	ag.Stop()
}
