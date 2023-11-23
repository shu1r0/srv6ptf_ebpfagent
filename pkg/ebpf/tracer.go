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

type LWTAttachRoute struct {
	Destination string `yaml:"destination"`
	Link        string `yaml:"link"`
	Priority    int    `yaml:"priority"`
	Table       int    `yaml:"table"`
	MTU         int    `yaml:"mtu"`
	GW          string `yaml:"gw"`
}

func ParseLWTAttachRoute(attach_rou LWTAttachRoute, encap netlink.Encap) (*netlink.Route, error) {
	_, dst, err := net.ParseCIDR(attach_rou.Destination)
	if err != nil {
		return nil, fmt.Errorf("parse cidr error : %s", err)
	}
	oif, err := netlink.LinkByName(attach_rou.Link)
	if err != nil {
		return nil, fmt.Errorf("link by name error : %s", err)
	}
	gw := net.ParseIP(attach_rou.GW)
	if attach_rou.GW != "" && gw == nil {
		return nil, fmt.Errorf("parse ip err : %s", err)
	}
	route := &netlink.Route{LinkIndex: oif.Attrs().Index, Dst: dst, Table: attach_rou.Table, Priority: attach_rou.Table, MTU: attach_rou.MTU, Encap: encap, Gw: gw}

	return route, nil
}

var PerfEventItemSize = 17

type TracerFlags struct {
	EnablePushPktIdXDP      bool
	EnablePushPktIdTCEgress bool
}

type TracingDataPlane struct {
	tracerObjects
	InIfaces               []string
	EIfaces                []string
	Efilters               []*netlink.BpfFilter
	Eqdiscs                []*netlink.GenericQdisc
	EndIIDRoutesConfig     []LWTAttachRoute
	XmitReadIdRoutesConfig []LWTAttachRoute
	InReadIdRoutesConfig   []LWTAttachRoute
	OutReadIdRoutesConfig  []LWTAttachRoute
	AddedRoutes            []*netlink.Route
	TracerFlags            TracerFlags
}

type AttachAllOptions struct {
	InIfaces   []string
	EIfaces    []string
	NoXDP      bool
	NoTCEgress bool
}

func NewAttachAllOptions() (*AttachAllOptions, error) {
	options := &AttachAllOptions{}
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	for _, l := range links {
		iface := l.Attrs().Name
		options.InIfaces = append(options.InIfaces, iface)
		options.EIfaces = append(options.EIfaces, iface)
	}
	return options, nil
}

func NewTracingDataPlane(options *ebpf.CollectionOptions, flags *TracerFlags) (*TracingDataPlane, error) {
	if flags == nil {
		flags = &TracerFlags{true, true}
	}
	dp := &TracingDataPlane{TracerFlags: *flags}

	spec, err := loadTracer()
	if err != nil {
		return nil, err
	}

	if _, ok := spec.Maps[".rodata"]; !ok {
		return nil, fmt.Errorf("could not find .rodata section to set argument\n")
	}
	if err := spec.RewriteConstants(map[string]interface{}{"ENABLE_PUSH_PKTID_XDP": flags.EnablePushPktIdXDP}); err != nil {
		return nil, fmt.Errorf("Rewrite ENABLE_PUSH_PKTID_XDP err: %s", err)
	}
	if err := spec.RewriteConstants(map[string]interface{}{"ENABLE_PUSH_PKTID_TC_EGRESS": flags.EnablePushPktIdTCEgress}); err != nil {
		return nil, fmt.Errorf("Rewrite ENABLE_PUSH_PKTID_TC_EGRESS err: %s", err)
	}

	if err := spec.LoadAndAssign(dp, options); err != nil {
		return nil, err
	}
	return dp, nil
}

func (obj *TracingDataPlane) AttachAll(options *AttachAllOptions) error {
	if options == nil {
		opt, err := NewAttachAllOptions()
		options = opt
		if err != nil {
			return err
		}
	}

	if !options.NoXDP {
		for _, i := range options.InIfaces {
			if err := obj.AttachIngress(i); err != nil {
				return err
			}
		}
	}
	if !options.NoTCEgress {
		for _, i := range options.EIfaces {
			if err := obj.AttachEgress(i); err != nil {
				return err
			}
		}
	}

	for _, r := range obj.EndIIDRoutesConfig {
		if err := obj.AttachSeg6LocalEndInsertId(r); err != nil {
			return err
		}
	}

	for _, r := range obj.XmitReadIdRoutesConfig {
		if err := obj.AttachLWTXmitReadId(r); err != nil {
			return err
		}
	}

	for _, r := range obj.InReadIdRoutesConfig {
		if err := obj.AttachLWTInReadId(r); err != nil {
			return err
		}
	}

	for _, r := range obj.OutReadIdRoutesConfig {
		if err := obj.AttachLWTOutReadId(r); err != nil {
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

func (obj *TracingDataPlane) AttachSeg6LocalEndInsertId(attach_rou LWTAttachRoute) error {
	var flags_end_bpf [nl.SEG6_LOCAL_MAX]bool
	flags_end_bpf[nl.SEG6_LOCAL_ACTION] = true
	flags_end_bpf[nl.SEG6_LOCAL_BPF] = true
	endBpfEncap := netlink.SEG6LocalEncap{Flags: flags_end_bpf, Action: nl.SEG6_LOCAL_ACTION_END_BPF}
	if err := endBpfEncap.SetProg(obj.EndInsertId.FD(), "End.Insert.ID"); err != nil {
		return err
	}

	route, err := ParseLWTAttachRoute(attach_rou, &endBpfEncap)
	if err != nil {
		return fmt.Errorf("Route parse error : %s", err)
	}
	if err := netlink.RouteAdd(route); err != nil {
		return fmt.Errorf("route add error : %s", err)
	}
	obj.AddedRoutes = append(obj.AddedRoutes, route)

	return nil
}

func (obj *TracingDataPlane) AttachLWTXmitReadId(attach_rou LWTAttachRoute) error {
	return obj.AttachLWT(nl.LWT_BPF_XMIT, obj.LwtxmitReadId.FD(), "XMIT.Read.ID", attach_rou)
}

func (obj *TracingDataPlane) AttachLWTInReadId(attach_rou LWTAttachRoute) error {
	return obj.AttachLWT(nl.LWT_BPF_IN, obj.LwtinReadId.FD(), "IN.Read.ID", attach_rou)
}

func (obj *TracingDataPlane) AttachLWTOutReadId(attach_rou LWTAttachRoute) error {
	return obj.AttachLWT(nl.LWT_BPF_OUT, obj.LwtoutReadId.FD(), "OUT.Read.ID", attach_rou)
}

func (obj *TracingDataPlane) AttachLWT(flag int, fd int, name string, attach_rou LWTAttachRoute) error {
	var flags_end_bpf [nl.SEG6_LOCAL_MAX]bool
	flags_end_bpf[nl.SEG6_LOCAL_ACTION] = true
	flags_end_bpf[nl.SEG6_LOCAL_BPF] = true
	bpfEncap := netlink.BpfEncap{}
	if err := bpfEncap.SetProg(flag, fd, name); err != nil {
		return err
	}

	route, err := ParseLWTAttachRoute(attach_rou, &bpfEncap)
	if err != nil {
		return fmt.Errorf("Route parse error : %s", err)
	}
	if err := netlink.RouteAdd(route); err != nil {
		return fmt.Errorf("route add error : %s", err)
	}
	obj.AddedRoutes = append(obj.AddedRoutes, route)

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
			if len(ev.RawSample) > PerfEventItemSize {
				pktinfo := NewPacketInfo(ev.RawSample[PerfEventItemSize:], int(item.Pktid), item.MonotonicTimestamp, int(item.Hookpoint))
				pktChan <- *pktinfo
			} else {
				log.Errorf("PacketInfoChan binary length %d", len(ev.RawSample))
			}
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
