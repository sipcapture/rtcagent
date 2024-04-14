package metric

import (
	"fmt"
	"time"

	"rtcagent/model"

	"github.com/prometheus/client_golang/prometheus"
)

// Namespace to use for all metrics
const prometheusNamespace = "rtcagent"

// const prom
var descs map[string]map[string]*prometheus.Desc
var mapping map[string]model.AggregatedMetricValue
var aggregated []model.AggregatedMetricValue

// Exporter is a ebpf_exporter instance implementing prometheus.Collector
type Exporter struct {
	enabledConfigsDesc *prometheus.Desc
	programInfoDesc    *prometheus.Desc
	deviceTCPRCVState  *prometheus.GaugeVec
}

// New creates a new exporter with the provided config
func NewExporter() (*Exporter, error) {
	enabledConfigsDesc := prometheus.NewDesc(
		prometheus.BuildFQName(prometheusNamespace, "", "enabled_configs"),
		"The set of enabled configs",
		[]string{"name"},
		nil,
	)

	programInfoDesc := prometheus.NewDesc(
		prometheus.BuildFQName(prometheusNamespace, "", "rtcagent_program_info"),
		"Info about ebpf programs",
		[]string{"config", "program", "tag", "id"},
		nil,
	)

	deviceTCPRCVState := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rtcagent_tcp_rcv_state",
		},
		[]string{
			"src_ip",
			"dst_ip",
			"src_port",
			"dst_port",
		},
	)

	mapping = make(map[string]model.AggregatedMetricValue)
	descs = make(map[string]map[string]*prometheus.Desc)

	return &Exporter{
		enabledConfigsDesc: enabledConfigsDesc,
		programInfoDesc:    programInfoDesc,
		deviceTCPRCVState:  deviceTCPRCVState,
	}, nil
}

func (e *Exporter) Add(pkt model.AggregatedMetricValue) {

	mapping["testkey"] = pkt
}

// Describe satisfies prometheus.Collector interface by sending descriptions
// for all metrics the exporter can possibly report
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {

	fmt.Println("Describe")

}

// Collect satisfies prometheus.Collector interface and sends all metrics
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {

	fmt.Println("Collect")

	//histograms := map[string]histogramWithLabels{}
	for name, metricValue := range mapping {

		programName := "rtcagent"

		if _, ok := descs[programName]; !ok {
			descs[programName] = map[string]*prometheus.Desc{}
		}

		if _, ok := descs[prometheusNamespace][name]; !ok {
			labelNames := append([]string{}, metricValue.Labels...)
			help := fmt.Sprintf("Help for %s", name)
			descs[programName][name] = prometheus.NewDesc(prometheus.BuildFQName(prometheusNamespace, "", name), help, labelNames, nil)
		}

		//prometheus.GaugeValue
		//ch <- prometheus.MustNewConstMetric(descs[programName][name], metricValue.Type, metricValue.Value, metricValue.Labels...)
		metric := e.deviceTCPRCVState.WithLabelValues(metricValue.Labels...)
		metric.Set(metricValue.Value)
		ch <- prometheus.NewMetricWithTimestamp(time.Now(), metric)
	}
}
