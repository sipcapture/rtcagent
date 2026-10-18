module rtcagent

go 1.26.0

require (
	github.com/VictoriaMetrics/fastcache v1.13.3
	github.com/buger/goterm v1.0.4
	github.com/cilium/ebpf v0.22.0
	github.com/gogo/protobuf v1.3.2
	github.com/prometheus/client_golang v1.25.0
	github.com/shuLhan/go-bindata v4.0.0+incompatible
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.10
	golang.org/x/crypto v0.57.0
	golang.org/x/sys v0.48.0
)

require github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect

require (
	github.com/avast/retry-go v3.0.0+incompatible // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/florianl/go-tc v0.4.8 // indirect
	github.com/gojue/ebpfmanager v0.6.0
	github.com/golang/snappy v1.0.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/mdlayher/netlink v1.11.2 // indirect
	github.com/mdlayher/socket v0.7.0 // indirect
	github.com/prometheus/client_model v0.6.3 // indirect
	github.com/prometheus/common v0.72.0 // indirect
	github.com/prometheus/procfs v0.22.0 // indirect
	github.com/vishvananda/netlink v1.3.1 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

replace github.com/google/gopacket v1.1.19 => github.com/cfc4n/gopacket v1.1.20
