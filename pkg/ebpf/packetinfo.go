package ebpf

type PacketInfo struct {
	Pkt                []byte
	PktId              int
	MonotoricTimestamp int
	Hookpoint          int
}

func NewPacketInfo(p []byte, pid int, monot int, hook int) *PacketInfo {
	return &PacketInfo{Pkt: p, PktId: pid, MonotoricTimestamp: monot, Hookpoint: hook}
}
