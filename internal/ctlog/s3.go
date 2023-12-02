package ctlog

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type S3Backend struct {
	getClient *s3.Client
	putClient *s3.Client
	bucket    string
	metrics   []prometheus.Collector
	log       *slog.Logger
}

func NewS3Backend(ctx context.Context, region, bucket string, l *slog.Logger) (*S3Backend, error) {
	counter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "s3_requests_total",
		},
		[]string{"action", "code"},
	)
	duration := prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "s3_request_duration_seconds",
			Objectives: map[float64]float64{0.5: 0.05, 0.75: 0.025, 0.9: 0.01, 0.99: 0.001},
			MaxAge:     1 * time.Minute,
			AgeBuckets: 6,
		},
		[]string{"action", "code"},
	)

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, err
	}

	getLabels := prometheus.Labels{"action": "get"}
	getTransport := http.RoundTripper(http.DefaultTransport.(*http.Transport).Clone())
	getTransport = promhttp.InstrumentRoundTripperCounter(counter.MustCurryWith(getLabels), getTransport)
	getTransport = promhttp.InstrumentRoundTripperDuration(duration.MustCurryWith(getLabels), getTransport)
	getCfg := cfg.Copy()
	getCfg.HTTPClient = &http.Client{Transport: getTransport}

	putLabels := prometheus.Labels{"action": "put"}
	putTransport := http.RoundTripper(http.DefaultTransport.(*http.Transport).Clone())
	putTransport = promhttp.InstrumentRoundTripperCounter(counter.MustCurryWith(putLabels), putTransport)
	putTransport = promhttp.InstrumentRoundTripperDuration(duration.MustCurryWith(putLabels), putTransport)
	putCfg := cfg.Copy()
	putCfg.HTTPClient = &http.Client{Transport: putTransport}

	return &S3Backend{
		getClient: s3.NewFromConfig(getCfg),
		putClient: s3.NewFromConfig(putCfg),
		bucket:    bucket,
		metrics:   []prometheus.Collector{counter, duration},
		log:       l,
	}, nil
}

var _ Backend = &S3Backend{}

func (s *S3Backend) Upload(ctx context.Context, key string, data []byte) error {
	return s.upload(ctx, key, bytes.NewReader(data), len(data), nil)
}

func (s *S3Backend) UploadCompressible(ctx context.Context, key string, data []byte) error {
	b := &bytes.Buffer{}
	w := gzip.NewWriter(b)
	if _, err := w.Write(data); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return s.upload(ctx, key, b, b.Len(), aws.String("gzip"))
}

func (s *S3Backend) upload(ctx context.Context, key string, data io.Reader, length int, ce *string) error {
	start := time.Now()
	// TODO: give up on slow requests and retry.
	_, err := s.putClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket:          aws.String(s.bucket),
		Key:             aws.String(key),
		Body:            data,
		ContentLength:   aws.Int64(int64(length)),
		ContentEncoding: ce,
	})
	s.log.DebugContext(ctx, "S3 PUT", "key", key, "size", length,
		"compress", ce != nil, "elapsed", time.Since(start), "error", err)
	return err
}

func (s *S3Backend) Fetch(ctx context.Context, key string) ([]byte, error) {
	s.log.DebugContext(ctx, "S3 GET", "key", key)
	out, err := s.getClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}
	defer out.Body.Close()
	return io.ReadAll(out.Body)
}

func (s *S3Backend) Metrics() []prometheus.Collector {
	return s.metrics
}
