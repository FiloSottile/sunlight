package witness

import (
	"reflect"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// TODO: add-checkpoint metrics partitioned by origin, outcome.
// TODO: log size gauge partitioned by origin.

type metrics struct {
	ReqCount    *prometheus.CounterVec
	ReqInFlight *prometheus.GaugeVec
	ReqDuration *prometheus.SummaryVec
}

func initMetrics() metrics {
	return metrics{
		ReqInFlight: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "http_in_flight_requests",
				Help: "Requests currently being served, by endpoint.",
			},
			[]string{"endpoint"},
		),
		ReqCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_total",
				Help: "HTTP requests served, by endpoint and response code.",
			},
			[]string{"endpoint", "code"},
		),
		ReqDuration: prometheus.NewSummaryVec(
			prometheus.SummaryOpts{
				Name:       "http_request_duration_seconds",
				Help:       "HTTP request serving latencies in seconds, by endpoint.",
				Objectives: map[float64]float64{0.5: 0.05, 0.75: 0.025, 0.9: 0.01, 0.99: 0.001},
				MaxAge:     1 * time.Minute,
				AgeBuckets: 6,
			},
			[]string{"endpoint"},
		),
	}
}

func (w *Witness) Metrics() []prometheus.Collector {
	var collectors []prometheus.Collector
	for i := 0; i < reflect.ValueOf(w.m).NumField(); i++ {
		collectors = append(collectors, reflect.ValueOf(w.m).Field(i).Interface().(prometheus.Collector))
	}
	return collectors
}
