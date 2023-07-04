package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type PerfEventItem struct {
	Pktid              uint64
	MonotonicTimestamp uint64
	Hookpoint          uint8
}

var PerfEventItemSize = 17

type TracingDataPlane struct {
	tracerObjects
	InIfaces []string
	EIfaces  []string
	Efilters []*netlink.BpfFilter
	Eqdiscs  []*netlink.GenericQdisc
}

func NewTracingDataPlane(options *ebpf.CollectionOptions) (*TracingDataPlane, error) {
	dp := &TracingDataPlane{}

	spec, err := loadTracer()
	if err != nil {
		return nil, err
	}
	// spec.RewriteConstants

	if err := spec.LoadAndAssign(dp, options); err != nil {
		return nil, err
	}
	return dp, nil
}

func (obj *TracingDataPlane) AttachAll() error {
	links, err := netlink.LinkList()
	if err != nil {
		return err
	}
	for _, l := range links {
		iface := l.Attrs().Name
		if err := obj.AttachIngress(iface); err != nil {
			return err
		}
		if err := obj.AttachEgress(iface); err != nil {
			return err
		}
	}

	return nil
}

func (obj *TracingDataPlane) DettachAll() {
	if err := obj.DettachIngresses(); err != nil {
		log.Fatal(err)
	}
	if err := obj.DettachEgresses(); err != nil {
		log.Fatal(err)
	}
}

func (obj *TracingDataPlane) AttachIngress(iface string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("Attach Ingress Error: %s", err)
	}

	if err := netlink.LinkSetXdpFd(link, obj.tracerPrograms.Ingress.FD()); err != nil {
		return err
	}

	obj.InIfaces = append(obj.InIfaces, iface)

	return nil
}

func (obj *TracingDataPlane) DettachIngresses() error {
	for _, iface := range obj.InIfaces {
		link, err := netlink.LinkByName(iface)
		if err != nil {
			return fmt.Errorf("Link Error: %s", err)
		}

		if err := netlink.LinkSetXdpFd(link, -1); err != nil {
			return fmt.Errorf("Dettach Ingress Error: %s", err)
		}
	}

	return nil
}

func (obj *TracingDataPlane) AttachEgress(iface string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}

	// Qdic
	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdic := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}
	if err := netlink.QdiscAdd(qdic); err != nil {
		return fmt.Errorf("Attach Egress Qdisc Add Error: %s", err)
	}
	obj.Eqdiscs = append(obj.Eqdiscs, qdic)

	// filter
	filterAttrs := netlink.FilterAttrs{
		LinkIndex: link.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}
	filter := &netlink.BpfFilter{
		FilterAttrs:  filterAttrs,
		Fd:           obj.Egress.FD(),
		Name:         "tle-egress",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil {
		return fmt.Errorf("Attach Egress Filter Add Error: %s", err)
	}

	obj.EIfaces = append(obj.EIfaces, iface)
	obj.Efilters = append(obj.Efilters, filter)

	return nil
}

func (obj *TracingDataPlane) DettachEgresses() error {
	for _, f := range obj.Efilters {
		if err := netlink.FilterDel(f); err != nil {
			return fmt.Errorf("Dettach Egress Error: %s", err)
		}
	}
	for _, q := range obj.Eqdiscs {
		if err := netlink.QdiscDel(q); err != nil {
			return fmt.Errorf("Dettach Qdisc Error: %s", err)
		}
	}
	return nil
}

func (obj *TracingDataPlane) PacketInfoChan() (chan PacketInfo, error) {
	pktChan := make(chan PacketInfo, 4096)
	perfEvent, err := perf.NewReader(obj.PerfMap, 4096)
	if err != nil {
		return nil, err
	}
	go func() {
		var item PerfEventItem
		for {
			ev, err := perfEvent.Read()
			if err != nil {
				if errors.Unwrap(err) == perf.ErrClosed {
					break
				}
				log.Errorf("PacketInfoChan perf read error: %s", err)
			}
			reader := bytes.NewReader(ev.RawSample)
			if err := binary.Read(reader, binary.LittleEndian, &item); err != nil {
				log.Errorf("PacketInfoChan read binary error: %s", err)
			}
			pktinfo := NewPacketInfo(ev.RawSample[PerfEventItemSize:], int(item.Pktid), item.MonotonicTimestamp, int(item.Hookpoint))
			pktChan <- *pktinfo
		}
	}()
	return pktChan, nil
}

func (obj *TracingDataPlane) SetMapConf(nid uint64) error {
	if err := obj.ConfigMap.Put(uint32(0), uint64(1)); err != nil {
		return fmt.Errorf("Config Map Error: %s", err)
	}
	if err := obj.ConfigMap.Put(uint32(1), nid); err != nil {
		return fmt.Errorf("Set Nodeid Error: %s", err)
	}
	if err := obj.CounterMap.Put(uint32(0), uint64(1)); err != nil {
		return fmt.Errorf("Counter Map Error: %s", err)
	}
	return nil
}
