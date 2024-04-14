package model

import (
	"github.com/prometheus/client_golang/prometheus"
)

// aggregatedMetricValue is a value after aggregation of equal label sets
type AggregatedMetricValue struct {
	// labels are decoded from the raw key
	Labels []string
	// value is the kernel map value
	Value float64
	//
	Type prometheus.ValueType
	//name
	Name string
}

type Label struct {
	Name string `yaml:"name"`
	Size uint   `yaml:"size"`
}
