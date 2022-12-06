package main

import (
	"flag"
	"fmt"
	api "github.com/shu1r0/srv6tracing_ebpfagent/pkg/agent"
	"os"
	"os/signal"
)

func main() {
	var (
		ip   = flag.String("ip", "[::]", "server ip address")
		port = flag.Int("port", 31000, "server port")
	)

	agent, err := api.NewTracingAgent(*ip, *port)
	if err != nil {
		panic(fmt.Errorf("New Agent Error: {}", err))
	}

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)

	fmt.Println("Start gRPC server.......")
	go agent.Start()

	<-quit
	agent.Stop()
	fmt.Println("Stop gRPC server.......")
}
