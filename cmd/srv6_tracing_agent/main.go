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
		logf = flag.String("log-file", "", "log file")
		logl = flag.String("log-level", "info", "log level (panic, fatal, error, warn, info, debug, trace)")
	)
	flag.Parse()

	log_utils.SetupLogger(*logl, *logf)

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
