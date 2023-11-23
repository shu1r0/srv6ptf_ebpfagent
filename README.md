# eBPF that assigns identifiers to SRH to track SRv6 packets.

## Install
```shell
git clone https://github.com/shu1r0/srv6tracing_ebpfagent.git
make install
```

## Usage
```
go run ./cmd/srv6_tracing_agent/main.go -h
Usage of srv6_ebpfagent:
  -conf-file string
        Configuration YAML file
  -e-ifaces string
        Interfaces for TC Egress (default all interfaces)
  -in-ifaces string
        Interfaces for XDP (default all interfaces)
  -ip string
        server ip address (default "[::]")
  -log-file string
        log file (default "/var/log/srv6_ptf/collector-agent.log")
  -log-level string
        log level (panic, fatal, error, warn, info, debug, trace) (default "info")
  -mode string
        mode to collect packet (packetmode or packetidmode) (default "packetidmode")
  -no-tc-egress
        Not attached to TC
  -no-xdp
        Not attached to XDP
  -port int
        server port (default 31000)
  -tc-egress-read-only
    
  -xdp-read-only
    
```

## Architecture

![architecture](./docs/images/network_flow.drawio.png)

