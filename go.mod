module github.com/shu1r0/srv6ptf_ebpfagent

go 1.17

require (
	github.com/cilium/ebpf v0.9.3
	github.com/google/gopacket v1.1.19
	github.com/sirupsen/logrus v1.9.0
	github.com/vishvananda/netlink v0.0.0-00010101000000-000000000000
	golang.org/x/sys v0.0.0-20220928140112-f11e5e49a4ec
	google.golang.org/grpc v1.50.1
	google.golang.org/protobuf v1.28.1
	gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c
)

require (
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/vishvananda/netns v0.0.0-20200728191858-db3c7e526aae // indirect
	golang.org/x/net v0.0.0-20201021035429-f5854403a974 // indirect
	golang.org/x/text v0.3.3 // indirect
	google.golang.org/genproto v0.0.0-20200526211855-cb27e3aa2013 // indirect
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
)

replace github.com/vishvananda/netlink => ./netlink
