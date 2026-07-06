package witness

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type metrics struct {
	KnownLogs          prometheus.Gauge
	MirroredLogs       prometheus.Gauge
	LogSize            *prometheus.GaugeVec
	AddCheckpointCount *prometheus.CounterVec
	SignSubtreeCount   *prometheus.CounterVec

	MirrorSize      *prometheus.GaugeVec
	MirrorNextEntry *prometheus.GaugeVec
	AddEntriesCount *prometheus.CounterVec

	MirrorEntries          *prometheus.CounterVec
	MirrorTiles            *prometheus.CounterVec
	MirrorEntryBytes       *prometheus.SummaryVec
	MirrorDataTileSize     *prometheus.SummaryVec
	MirrorDataTileGzipSize *prometheus.SummaryVec

	ListPullErrors *prometheus.CounterVec
	ListPullTime   *prometheus.GaugeVec

	ReqCount    *prometheus.CounterVec
	ReqInFlight *prometheus.GaugeVec
	ReqDuration *prometheus.SummaryVec
	ReqSize     *prometheus.SummaryVec
}

func initMetrics() metrics {
	return metrics{
		KnownLogs: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "known_logs",
			Help: "Number of logs known to the witness.",
		}),
		MirroredLogs: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "mirrored_logs",
			Help: "Number of logs mirrored by the witness.",
		}),
		LogSize: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "log_entries_total",
				Help: "Size of the latest checkpoint, by log origin.",
			},
			[]string{"origin"},
		),
		AddCheckpointCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "add_checkpoint_requests_total",
				Help: "Total number of add-checkpoint requests processed, by log origin.",
			},
			[]string{"error", "origin", "progress"},
		),
		SignSubtreeCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "sign_subtree_requests_total",
				Help: "Total number of sign-subtree requests processed, by log origin.",
			},
			[]string{"error", "origin"},
		),

		MirrorSize: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "mirror_log_entries_total",
				Help: "Size of the latest mirror checkpoint, by log origin.",
			},
			[]string{"origin"},
		),
		MirrorNextEntry: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "mirror_next_entry",
				Help: "Number of entries durably uploaded to the mirror, at or ahead of the mirror checkpoint, by log origin.",
			},
			[]string{"origin"},
		),
		AddEntriesCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "add_entries_requests_total",
				Help: "Total number of add-entries requests processed, by log origin.",
			},
			[]string{"error", "origin"},
		),

		MirrorEntries: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "mirror_uploaded_entries_total",
				Help: "Number of new entries uploaded via add-entries, by log origin.",
			},
			[]string{"origin"},
		),
		MirrorTiles: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "mirror_uploaded_tiles_total",
				Help: "Number of tiles uploaded via add-entries, including partials, by log origin and whether they are tiles cut at the committed checkpoint.",
			},
			[]string{"origin", "cut"},
		),
		MirrorEntryBytes: prometheus.NewSummaryVec(
			prometheus.SummaryOpts{
				Name:       "mirror_entry_bytes",
				Help:       "Size of individual entries uploaded via add-entries, by log origin.",
				Objectives: map[float64]float64{0.5: 0.05, 0.99: 0.001},
				MaxAge:     1 * time.Minute,
				AgeBuckets: 6,
			},
			[]string{"origin"},
		),
		MirrorDataTileSize: prometheus.NewSummaryVec(
			prometheus.SummaryOpts{
				Name:       "mirror_data_tiles_bytes",
				Help:       "Uncompressed size of uploaded mirror data tiles, including partials, by log origin.",
				Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
				MaxAge:     1 * time.Minute,
				AgeBuckets: 6,
			},
			[]string{"origin"},
		),
		MirrorDataTileGzipSize: prometheus.NewSummaryVec(
			prometheus.SummaryOpts{
				Name:       "mirror_data_tiles_gzip_bytes",
				Help:       "Compressed size of uploaded mirror data tiles, including partials, by log origin.",
				Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
				MaxAge:     1 * time.Minute,
				AgeBuckets: 6,
			},
			[]string{"origin"},
		),

		ListPullErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "log_list_pull_errors_total",
				Help: "Number of failed log list pulls, by list URL or path.",
			},
			[]string{"list"},
		),
		ListPullTime: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "log_list_pull_timestamp_seconds",
				Help: "Timestamp of the last successful pull of each log list.",
			},
			[]string{"list"},
		),

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
		ReqSize: prometheus.NewSummaryVec(
			prometheus.SummaryOpts{
				Name:       "http_request_size_bytes",
				Help:       "HTTP request sizes in bytes, by endpoint.",
				Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
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
	return append(collectors, w.c.Backend.Metrics()...)
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
	if subCatErr := new(categoryError); errors.As(err, subCatErr) {
		category = category + ": " + subCatErr.category
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

// errorLabel returns a bounded metrics label value for the given error: the
// fixed message of conflict errors, or the error's category.
func errorLabel(err error) string {
	switch err.(type) {
	case *conflictError, *mirrorConflictError:
		return err.Error()
	}
	return errorCategory(err)
}
