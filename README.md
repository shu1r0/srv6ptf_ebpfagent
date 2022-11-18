# 名前どうする？
- エージェント
- SRv6 Path Tracing Framework



## TODO
- Mapじゃなくて，定数書き換えは？

## わからん
- パケットのサイズ変更 (TLV) の挿入はどうするの？

## REFERENCES (XDP)
- https://github.com/xdp-project/xdp-tutorial/tree/master/tracing04-xdp-tcpdump
- https://github.com/opennetworkinglab/int-host-reporter
- [Tutorial: Packet02 - packet rewriting](https://github.com/xdp-project/xdp-tutorial/tree/master/packet02-rewriting), https://github.com/xdp-project/xdp-tutorial/blob/master/common/rewrite_helpers.h
- [takehaya/Vinbero](https://github.com/takehaya/Vinbero)
- [terassyi/go-xdp-examples](https://github.com/terassyi/go-xdp-examples)
- [BPF In Depth: Communicating with Userspace](https://blogs.oracle.com/linux/post/bpf-in-depth-communicating-with-userspace)
- [cilinum/ebpf ebpf/examples](https://github.com/cilium/ebpf/tree/v0.9.3/examples)


## REFERENCES (SRv6)
- https://github.com/netgroup/hike/blob/master/hike/ipv6_gen_prog.h
- https://github.com/torvalds/linux/blob/e2b542100719a93f8cdf6d90185410d38a57a4c1/tools/include/uapi/linux/seg6.h
- https://github.com/takehaya/Vinbero/blob/e35cfdc1b06b083d5a7aae53e1ba99e65027ec15/src/srv6_structs.h
- https://github.com/PolynomialDivision/xdp-srv6-remover/blob/master/src/srv6_kern.c# srv6tracking_ebpfagent
