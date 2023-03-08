package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type perf_event_item tracer ../../bpf/srv6_tracer.c -- -I../../bpf/ -I/usr/include/
