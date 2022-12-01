package ebpf

import (
	"github.com/cilium/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go telemetry ../../bpf/telemetry.c -- -I../../bpf/ -I/usr/include/

func newBPFObject(options *ebpf.CollectionOptions) (*telemetryObjects, error) {
	// return co, nil
	obj := &telemetryObjects{}
	if err := loadTelemetryObjects(obj, options); err != nil {
		return nil, err
	}

	return obj, nil
}
