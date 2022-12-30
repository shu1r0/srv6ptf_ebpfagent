package ebpf

type PacketInfo struct {
	Pkt                []byte
	PktId              int
	MonotoricTimestamp uint64
	Hookpoint          int
}

func NewPacketInfo(p []byte, pid int, monot uint64, hook int) *PacketInfo {
	return &PacketInfo{Pkt: p, PktId: pid, MonotoricTimestamp: monot, Hookpoint: hook}
}
