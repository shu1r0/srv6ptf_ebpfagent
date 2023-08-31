// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64be || armbe || mips || mips64 || mips64p32 || ppc64 || s390 || s390x || sparc || sparc64
// +build arm64be armbe mips mips64 mips64p32 ppc64 s390 s390x sparc sparc64

package ebpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type tracerPerfEventItem struct {
	Pktid              uint64
	MonotonicTimestamp uint64
	Hookpoint          uint8
}

// loadTracer returns the embedded CollectionSpec for tracer.
func loadTracer() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_TracerBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load tracer: %w", err)
	}

	return spec, err
}

// loadTracerObjects loads tracer and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*tracerObjects
//	*tracerPrograms
//	*tracerMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadTracerObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadTracer()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// tracerSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tracerSpecs struct {
	tracerProgramSpecs
	tracerMapSpecs
}

// tracerSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tracerProgramSpecs struct {
	Egress        *ebpf.ProgramSpec `ebpf:"egress"`
	EndInsertId   *ebpf.ProgramSpec `ebpf:"end_insert_id"`
	Ingress       *ebpf.ProgramSpec `ebpf:"ingress"`
	LwtinReadId   *ebpf.ProgramSpec `ebpf:"lwtin_read_id"`
	LwtoutReadId  *ebpf.ProgramSpec `ebpf:"lwtout_read_id"`
	LwtxmitReadId *ebpf.ProgramSpec `ebpf:"lwtxmit_read_id"`
}

// tracerMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tracerMapSpecs struct {
	ConfigMap  *ebpf.MapSpec `ebpf:"config_map"`
	CounterMap *ebpf.MapSpec `ebpf:"counter_map"`
	PerfMap    *ebpf.MapSpec `ebpf:"perf_map"`
}

// tracerObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadTracerObjects or ebpf.CollectionSpec.LoadAndAssign.
type tracerObjects struct {
	tracerPrograms
	tracerMaps
}

func (o *tracerObjects) Close() error {
	return _TracerClose(
		&o.tracerPrograms,
		&o.tracerMaps,
	)
}

// tracerMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadTracerObjects or ebpf.CollectionSpec.LoadAndAssign.
type tracerMaps struct {
	ConfigMap  *ebpf.Map `ebpf:"config_map"`
	CounterMap *ebpf.Map `ebpf:"counter_map"`
	PerfMap    *ebpf.Map `ebpf:"perf_map"`
}

func (m *tracerMaps) Close() error {
	return _TracerClose(
		m.ConfigMap,
		m.CounterMap,
		m.PerfMap,
	)
}

// tracerPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadTracerObjects or ebpf.CollectionSpec.LoadAndAssign.
type tracerPrograms struct {
	Egress        *ebpf.Program `ebpf:"egress"`
	EndInsertId   *ebpf.Program `ebpf:"end_insert_id"`
	Ingress       *ebpf.Program `ebpf:"ingress"`
	LwtinReadId   *ebpf.Program `ebpf:"lwtin_read_id"`
	LwtoutReadId  *ebpf.Program `ebpf:"lwtout_read_id"`
	LwtxmitReadId *ebpf.Program `ebpf:"lwtxmit_read_id"`
}

func (p *tracerPrograms) Close() error {
	return _TracerClose(
		p.Egress,
		p.EndInsertId,
		p.Ingress,
		p.LwtinReadId,
		p.LwtoutReadId,
		p.LwtxmitReadId,
	)
}

func _TracerClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed tracer_bpfeb.o
var _TracerBytes []byte
