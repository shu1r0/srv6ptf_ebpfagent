package main

import (
	"flag"
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
	)
	flag.Parse()

	if len(*logf) <= 0 {
		log.SetOutput(os.Stdout)
	} else {
		f, err := os.Create(*logf)
		if err != nil {
			log.Panic(err)
		}
		defer func() {
			if err := f.Close(); err != nil {
				log.Panic(err)
			}
		}()

		log.SetOutput(f)
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
