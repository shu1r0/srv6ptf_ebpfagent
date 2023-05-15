# eBPF that assigns identifiers to SRH to track SRv6 packets.

## Install
```shell
git clone https://github.com/shu1r0/srv6tracing_ebpfagent.git
make install
```

## Usage
```
go run ./cmd/srv6_tracing_agent/main.go -h
Usage of /tmp/go-build941929647/b001/exe/main:
  -ip string
        server ip address (default "[::]")
  -log-file string
        log file (default "/var/log/srv6_ptf/collector-agent.log")
  -log-level string
        log level (panic, fatal, error, warn, info, debug, trace) (default "info")
  -port int
        server port (default 31000)
```

## Architecture

![architecture](./docs/images/network_flow.drawio.png)

