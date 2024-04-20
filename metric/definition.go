package metric

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// TCP Latency
	latencyTCP = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "tcp_latency",
		Help: "latency of tcp connection"},
		[]string{"node_id", "src_ip", "dst_ip", "src_port", "dst_port"})
)
