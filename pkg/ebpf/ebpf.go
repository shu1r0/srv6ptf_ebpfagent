package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go tracer ../../bpf/srv6_tracer.c -- -I../../bpf/ -I/usr/include/
