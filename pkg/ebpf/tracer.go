package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink/nl"

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

type Seg6LocalEndInsertIdRoute struct {
	Destination string `yaml:"destination"`
	Link        string `yaml:"link"`
}

type LWTReadIdRoute struct {
	Destination string `yaml:"destination"`
	Link        string `yaml:"link"`
}

var PerfEventItemSize = 17

type TracingDataPlane struct {
	tracerObjects
	InIfaces               []string
	EIfaces                []string
	Efilters               []*netlink.BpfFilter
	Eqdiscs                []*netlink.GenericQdisc
	EndIIDRoutesConfig     []Seg6LocalEndInsertIdRoute
	XmitReadIdRoutesConfig []LWTReadIdRoute
	InReadIdRoutesConfig   []LWTReadIdRoute
	OutReadIdRoutesConfig  []LWTReadIdRoute
	AddedRoutes            []*netlink.Route
}

type AttachAllOptions struct {
	InIfaces []string
	EIfaces  []string
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

func (obj *TracingDataPlane) AttachAll(options *AttachAllOptions) error {
	if options == nil {
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
	} else {
		for _, i := range options.InIfaces {
			if err := obj.AttachIngress(i); err != nil {
				return err
			}
		}
		for _, i := range options.EIfaces {
			if err := obj.AttachEgress(i); err != nil {
				return err
			}
		}
	}

	for _, r := range obj.EndIIDRoutesConfig {
		if err := obj.AttachSeg6LocalEndInsertId(r.Destination, r.Link); err != nil {
			return err
		}
	}

	for _, r := range obj.XmitReadIdRoutesConfig {
		if err := obj.AttachLWTXmitReadId(r.Destination, r.Link); err != nil {
			return err
		}
	}

	for _, r := range obj.InReadIdRoutesConfig {
		if err := obj.AttachLWTInReadId(r.Destination, r.Link); err != nil {
			return err
		}
	}

	for _, r := range obj.OutReadIdRoutesConfig {
		if err := obj.AttachLWTOutReadId(r.Destination, r.Link); err != nil {
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
	if err := obj.DettachAllRoutes(); err != nil {
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

func (obj *TracingDataPlane) AttachSeg6LocalEndInsertId(dst_s string, link string) error {
	var flags_end_bpf [nl.SEG6_LOCAL_MAX]bool
	flags_end_bpf[nl.SEG6_LOCAL_ACTION] = true
	flags_end_bpf[nl.SEG6_LOCAL_BPF] = true
	endBpfEncap := netlink.SEG6LocalEncap{Flags: flags_end_bpf, Action: nl.SEG6_LOCAL_ACTION_END_BPF}
	if err := endBpfEncap.SetProg(obj.EndInsertId.FD(), "End.Insert.ID"); err != nil {
		return err
	}

	_, dst, err := net.ParseCIDR(dst_s)
	if err != nil {
		return fmt.Errorf("parse cidr error : %s", err)
	}
	oif, err := netlink.LinkByName(link)
	if err != nil {
		return fmt.Errorf("link by name error : %s", err)
	}
	route := netlink.Route{LinkIndex: oif.Attrs().Index, Dst: dst, Encap: &endBpfEncap}
	if err := netlink.RouteAdd(&route); err != nil {
		return fmt.Errorf("route add error : %s", err)
	}
	obj.AddedRoutes = append(obj.AddedRoutes, &route)

	return nil
}

func (obj *TracingDataPlane) AttachLWTXmitReadId(dst_s string, link string) error {
	return obj.AttachLWT(nl.LWT_BPF_XMIT, obj.LwtxmitReadId.FD(), "XMIT.Read.ID", dst_s, link)
}

func (obj *TracingDataPlane) AttachLWTInReadId(dst_s string, link string) error {
	return obj.AttachLWT(nl.LWT_BPF_IN, obj.LwtinReadId.FD(), "IN.Read.ID", dst_s, link)
}

func (obj *TracingDataPlane) AttachLWTOutReadId(dst_s string, link string) error {
	return obj.AttachLWT(nl.LWT_BPF_OUT, obj.LwtoutReadId.FD(), "OUT.Read.ID", dst_s, link)
}

func (obj *TracingDataPlane) AttachLWT(flag int, fd int, name string, dst_s string, link string) error {
	var flags_end_bpf [nl.SEG6_LOCAL_MAX]bool
	flags_end_bpf[nl.SEG6_LOCAL_ACTION] = true
	flags_end_bpf[nl.SEG6_LOCAL_BPF] = true
	bpfEncap := netlink.BpfEncap{}
	if err := bpfEncap.SetProg(flag, fd, name); err != nil {
		return err
	}

	_, dst, err := net.ParseCIDR(dst_s)
	if err != nil {
		return fmt.Errorf("parse cidr error : %s", err)
	}
	oif, err := netlink.LinkByName(link)
	if err != nil {
		return fmt.Errorf("link by name error : %s", err)
	}
	route := netlink.Route{LinkIndex: oif.Attrs().Index, Dst: dst, Encap: &bpfEncap}
	if err := netlink.RouteAdd(&route); err != nil {
		return fmt.Errorf("route add error : %s", err)
	}
	obj.AddedRoutes = append(obj.AddedRoutes, &route)

	return nil
}

func (obj *TracingDataPlane) DettachAllRoutes() error {
	for _, r := range obj.AddedRoutes {
		if err := netlink.RouteDel(r); err != nil {
			return fmt.Errorf("delete route error: %s", err)
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
