/*
LINK - http://github.com/sipcapture/rtcagent

Copyright (C) 2023 QXIP B.V.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// Package metrics provides process-wide Prometheus metrics for rtcagent.
//
// The collectors use the default Prometheus registry, so they are exported by
// the /metrics endpoint served by the metric package.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// EventsDropped counts events discarded because the incoming event queue
	// was full.
	EventsDropped = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "rtcagent",
		Name:      "events_dropped_total",
		Help:      "Events dropped because the incoming event queue was full.",
	})

	// HEPSendErrors counts HEP messages that could not be delivered.
	HEPSendErrors = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "rtcagent",
		Name:      "hep_send_errors_total",
		Help:      "HEP messages that could not be delivered.",
	})

	// HEPReconnects counts successful HEP reconnections after a failed send.
	HEPReconnects = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "rtcagent",
		Name:      "hep_reconnects_total",
		Help:      "Successful HEP reconnections after a failed send.",
	})

	// HEPQueueLength reports how many HEP messages are waiting to be sent.
	HEPQueueLength = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "rtcagent",
		Name:      "hep_queue_length",
		Help:      "HEP messages waiting to be sent.",
	})
)
