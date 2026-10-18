package metric

import (
	"log"
	"net"
	"net/http"
	"rtcagent/model"
	"strings"
	"sync"
	"time"

	"github.com/VictoriaMetrics/fastcache"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	invite    = "INVITE"
	register  = "REGISTER"
	cacheSize = 60 * 1024 * 1024
)

type Prometheus struct {
	TargetEmpty bool
	TargetIP    []string
	TargetName  []string
	TargetMap   map[string]string
	TargetConf  *sync.RWMutex
	cache       *fastcache.Cache
	s           *http.Server
}

func (p *Prometheus) setup() (err error) {
	p.TargetConf = new(sync.RWMutex)
	p.TargetIP = strings.Split("10.0.0.1", ",")
	p.TargetName = strings.Split("test", ",")
	p.cache = fastcache.New(cacheSize)

	/*
		err = prometheus.Register(version_collector.NewCollector("rtcagent"))
		if err != nil {
			log.Fatalf("Error registering version collector: %s", err)
		}

		p.exporter, err = NewExporter()
		if err != nil {
			log.Fatalf("Error creating exporter: %s", err)
		}

		err = prometheus.Register(p.exporter)
		if err != nil {
			log.Fatalf("Error registering exporter: %s", err)
		}
	*/

	metricsPath := "/metrics"
	listenAddress := ":9435"

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(`<html>
				<head><title>eBPF Exporter</title></head>
				<body>
				<h1>eBPF Exporter</h1>
				<p><a href="` + metricsPath + `">Metrics</a></p>
				</body>
				</html>`)); err != nil {
			log.Printf("error sending response body: %v", err)
		}
	})

	p.s = &http.Server{
		Addr:           listenAddress,
		Handler:        mux,
		ReadTimeout:    0, // 1 * time.Minute,
		WriteTimeout:   30 * time.Minute,
		MaxHeaderBytes: 1 << 20,
	}

	go func() {

		l, err := net.Listen("tcp", listenAddress)

		if err != nil {
			log.Printf("metrics listener error: %v", err)
			return
		}

		//fmt.Println(`{"server_state":"listening"}`)
		if err := p.s.Serve(l); err != nil && err != http.ErrServerClosed {
			log.Printf("metrics server stopped: %v", err)
		}
	}()

	return err
}

func (p *Prometheus) expose(hCh chan model.AggregatedMetricValue) {
	for pkt := range hCh {

		//fmt.Println(pkt.Name)
		if pkt.IntType == 2 {
			latencyTCP.WithLabelValues(pkt.Labels...).Set(pkt.Value)
		}
	}
}
