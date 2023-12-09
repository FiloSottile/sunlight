package ctlog

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type metrics struct {
	ReqCount    *prometheus.CounterVec
	ReqInFlight *prometheus.GaugeVec
	ReqDuration *prometheus.SummaryVec

	SeqCount        *prometheus.CounterVec
	SeqPoolSize     prometheus.Summary
	SeqDuration     prometheus.Summary
	SeqLeafSize     prometheus.Summary
	SeqTiles        prometheus.Counter
	SeqDataTileSize prometheus.Summary

	TreeTime prometheus.Gauge
	TreeSize prometheus.Gauge

	ConfigRoots prometheus.Gauge
	ConfigStart prometheus.Gauge
	ConfigEnd   prometheus.Gauge

	Issuers prometheus.Gauge

	AddChainCount *prometheus.CounterVec
	AddChainWait  prometheus.Summary

	CacheGetDuration prometheus.Summary
	CachePutDuration prometheus.Summary
	CachePutErrors   prometheus.Counter
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

		SeqCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "sequencing_rounds_total",
				Help: "Number of sequencing rounds, by error category if failed.",
			},
			[]string{"error"},
		),
		SeqPoolSize: prometheus.NewSummary(
			prometheus.SummaryOpts{
				Name:       "sequencing_pool_entries",
				Help:       "Number of entries in the pools being sequenced.",
				Objectives: map[float64]float64{0.5: 0.05, 0.99: 0.001},
				MaxAge:     1 * time.Minute,
				AgeBuckets: 6,
			},
		),
		SeqDuration: prometheus.NewSummary(
			prometheus.SummaryOpts{
				Name:       "sequencing_duration_seconds",
				Help:       "Duration of sequencing rounds, successful or not.",
				Objectives: map[float64]float64{0.5: 0.05, 0.75: 0.025, 0.9: 0.01, 0.99: 0.001},
				MaxAge:     1 * time.Minute,
				AgeBuckets: 6,
			},
		),
		SeqLeafSize: prometheus.NewSummary(
			prometheus.SummaryOpts{
				Name:       "sequencing_leaf_bytes",
				Help:       "Size of leaves in sequencing rounds, successful or not.",
				Objectives: map[float64]float64{0.5: 0.05, 0.99: 0.001},
				MaxAge:     1 * time.Minute,
				AgeBuckets: 6,
			},
		),
		SeqTiles: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "sequencing_uploaded_tiles_total",
				Help: "Number of tiles uploaded in successful rounds, including partials.",
			},
		),
		SeqDataTileSize: prometheus.NewSummary(
			prometheus.SummaryOpts{
				Name:       "sequencing_data_tiles_bytes",
				Help:       "Uncompressed size of uploaded data tiles, including partials.",
				Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
				MaxAge:     1 * time.Minute,
				AgeBuckets: 6,
			},
		),

		TreeTime: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "tree_timestamp_seconds",
				Help: "Timestamp of the latest published tree head.",
			},
		),
		TreeSize: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "tree_size_leaves_total",
				Help: "Size of the latest published tree head.",
			},
		),

		ConfigRoots: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "config_roots_total",
				Help: "Number of accepted roots.",
			},
		),
		ConfigStart: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "config_notafter_start_timestamp_seconds",
				Help: "Start of the NotAfter accepted period.",
			},
		),
		ConfigEnd: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "config_notafter_end_timestamp_seconds",
				Help: "End of the NotAfter accepted period.",
			},
		),

		Issuers: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "issuers_certs_total",
				Help: "Number of certificates in the issuers bundle.",
			},
		),

		AddChainCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "addchain_requests_total",
				Help: "Number of add-[pre-]chain requests, by chain characteristics and errors if any.",
			},
			[]string{"error", "issuer", "root", "precert", "preissuer", "chain_len", "source"},
		),
		AddChainWait: prometheus.NewSummary(
			prometheus.SummaryOpts{
				Name:       "addchain_wait_seconds",
				Help:       "Duration of add-[pre-]chain pauses waiting for a leaf to be sequenced, excluding deduplicated entries.",
				Objectives: map[float64]float64{0.5: 0.05, 0.75: 0.025, 0.9: 0.01, 0.99: 0.001},
				MaxAge:     1 * time.Minute,
				AgeBuckets: 6,
			},
		),

		CacheGetDuration: prometheus.NewSummary(
			prometheus.SummaryOpts{
				Name:       "cache_get_duration_seconds",
				Help:       "Duration of individual deduplication cache lookups.",
				Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
				MaxAge:     1 * time.Minute,
				AgeBuckets: 6,
			},
		),
		CachePutDuration: prometheus.NewSummary(
			prometheus.SummaryOpts{
				Name:       "cache_put_duration_seconds",
				Help:       "Duration of batch deduplication cache inserts.",
				Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
				MaxAge:     1 * time.Minute,
				AgeBuckets: 6,
			},
		),
		CachePutErrors: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "cache_put_errors_total",
				Help: "Number of failed deduplication cache inserts.",
			},
		),
	}
}

func (l *Log) Metrics() []prometheus.Collector {
	var collectors []prometheus.Collector
	for i := 0; i < reflect.ValueOf(l.m).NumField(); i++ {
		collectors = append(collectors, reflect.ValueOf(l.m).Field(i).Interface().(prometheus.Collector))
	}
	return append(collectors, l.c.Backend.Metrics()...)
}

type categoryError struct {
	category string
	err      error
}

func (e categoryError) Error() string { return e.err.Error() }
func (e categoryError) Unwrap() error { return e.err }

// fmtErrorf returns an error like fmt.Errorf, but with a category derived from
// the format suitable for a metrics label.
func fmtErrorf(format string, args ...interface{}) error {
	category, _, _ := strings.Cut(format, "%")
	category = strings.TrimSpace(category)
	category = strings.TrimSuffix(category, ":")
	err := fmt.Errorf(format, args...)
	if err, ok := errors.Unwrap(err).(categoryError); ok {
		category = category + ": " + err.category
	}
	return categoryError{category: category, err: err}
}

func errorCategory(err error) string {
	var categoryErr categoryError
	if errors.As(err, &categoryErr) {
		return categoryErr.category
	}
	return "?"
}
