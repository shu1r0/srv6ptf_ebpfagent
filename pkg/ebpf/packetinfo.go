package ebpf

type PacketInfo struct {
	Pkt                []byte
	PktId              uint
	MonotoricTimestamp uint64
	Hookpoint          uint
}

func NewPacketInfo(p []byte, pid int, monot uint64, hook int) *PacketInfo {
	return &PacketInfo{Pkt: p, PktId: uint(pid), MonotoricTimestamp: monot, Hookpoint: uint(hook)}
}
