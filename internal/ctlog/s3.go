package ctlog

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type S3Backend struct {
	client        *s3.Client
	bucket        string
	metrics       []prometheus.Collector
	uploadSize    prometheus.Summary
	compressRatio prometheus.Summary
	hedgeRequests prometheus.Counter
	hedgeWins     prometheus.Counter
	log           *slog.Logger
}

func NewS3Backend(ctx context.Context, region, bucket, endpoint string, l *slog.Logger) (*S3Backend, error) {
	counter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "s3_requests_total",
			Help: "S3 HTTP requests performed, by method and response code.",
		},
		[]string{"method", "code"},
	)
	duration := prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "s3_request_duration_seconds",
			Help:       "S3 HTTP request latencies, by method and response code.",
			Objectives: map[float64]float64{0.5: 0.05, 0.75: 0.025, 0.9: 0.01, 0.99: 0.001},
			MaxAge:     1 * time.Minute,
			AgeBuckets: 6,
		},
		[]string{"method", "code"},
	)
	uploadSize := prometheus.NewSummary(
		prometheus.SummaryOpts{
			Name:       "s3_upload_size_bytes",
			Help:       "S3 (compressed) body size in bytes for object puts.",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
			MaxAge:     1 * time.Minute,
			AgeBuckets: 6,
		},
	)
	compressRatio := prometheus.NewSummary(
		prometheus.SummaryOpts{
			Name:       "s3_compress_ratio",
			Help:       "Ratio of compressed to uncompressed body size for compressible object puts.",
			MaxAge:     1 * time.Minute,
			AgeBuckets: 6,
		},
	)
	hedgeRequests := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "s3_hedges_total",
			Help: "S3 hedge requests that were launched because the main request was too slow.",
		},
	)
	hedgeWins := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "s3_hedges_successful_total",
			Help: "S3 hedge requests that completed before the main request.",
		},
	)

	transport := http.RoundTripper(http.DefaultTransport.(*http.Transport).Clone())
	transport = promhttp.InstrumentRoundTripperCounter(counter, transport)
	transport = promhttp.InstrumentRoundTripperDuration(duration, transport)

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region),
		config.WithHTTPClient(&http.Client{Transport: transport}),
		config.WithRetryer(func() aws.Retryer {
			return retry.AddWithMaxBackoffDelay(retry.NewStandard(), 5*time.Millisecond)
		}))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config for S3 backend: %w", err)
	}

	return &S3Backend{
		client: s3.NewFromConfig(cfg, func(o *s3.Options) {
			if endpoint != "" {
				o.BaseEndpoint = aws.String(endpoint)
			}
		}),
		bucket: bucket,
		metrics: []prometheus.Collector{counter, duration,
			uploadSize, compressRatio, hedgeRequests, hedgeWins},
		uploadSize:    uploadSize,
		compressRatio: compressRatio,
		hedgeRequests: hedgeRequests,
		hedgeWins:     hedgeWins,
		log:           l,
	}, nil
}

var _ Backend = &S3Backend{}

func (s *S3Backend) Upload(ctx context.Context, key string, data []byte) error {
	return s.upload(ctx, key, data, len(data), nil)
}

func (s *S3Backend) UploadCompressible(ctx context.Context, key string, data []byte) error {
	b := &bytes.Buffer{}
	w := gzip.NewWriter(b)
	if _, err := w.Write(data); err != nil {
		return fmtErrorf("failed to compress %q: %w", key, err)
	}
	if err := w.Close(); err != nil {
		return fmtErrorf("failed to compress %q: %w", key, err)
	}
	s.compressRatio.Observe(float64(b.Len()) / float64(len(data)))
	return s.upload(ctx, key, b.Bytes(), b.Len(), aws.String("gzip"))
}

func (s *S3Backend) upload(ctx context.Context, key string, data []byte, length int, ce *string) error {
	start := time.Now()
	s.uploadSize.Observe(float64(length))
	ctx, cancel := context.WithCancelCause(ctx)
	hedgeErr := make(chan error, 1)
	go func() {
		timer := time.NewTimer(75 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
		case <-timer.C:
			s.hedgeRequests.Inc()
			_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
				Bucket:          aws.String(s.bucket),
				Key:             aws.String(key),
				Body:            bytes.NewReader(data),
				ContentLength:   aws.Int64(int64(length)),
				ContentEncoding: ce,
			})
			s.log.DebugContext(ctx, "S3 PUT hedge", "key", key, "err", err)
			hedgeErr <- err
			cancel(errors.New("competing request succeeded"))
		}
	}()
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:          aws.String(s.bucket),
		Key:             aws.String(key),
		Body:            bytes.NewReader(data),
		ContentLength:   aws.Int64(int64(length)),
		ContentEncoding: ce,
	})
	select {
	case err = <-hedgeErr:
		s.hedgeWins.Inc()
	default:
		cancel(errors.New("competing request succeeded"))
	}
	s.log.DebugContext(ctx, "S3 PUT", "key", key, "size", length,
		"compress", ce != nil, "elapsed", time.Since(start), "err", err)
	if err != nil {
		return fmtErrorf("failed to upload %q to S3: %w", key, err)
	}
	return nil
}

func (s *S3Backend) Fetch(ctx context.Context, key string) ([]byte, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		s.log.DebugContext(ctx, "S3 GET", "key", key, "err", err)
		return nil, fmtErrorf("failed to fetch %q from S3: %w", key, err)
	}
	defer out.Body.Close()
	s.log.DebugContext(ctx, "S3 GET", "key", key,
		"size", out.ContentLength, "encoding", out.ContentEncoding)
	body := out.Body
	if out.ContentEncoding != nil && *out.ContentEncoding == "gzip" {
		body, err = gzip.NewReader(out.Body)
		if err != nil {
			return nil, fmtErrorf("failed to decompress %q from S3: %w", key, err)
		}
	}
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, fmtErrorf("failed to read %q from S3: %w", key, err)
	}
	return data, nil
}

func (s *S3Backend) Metrics() []prometheus.Collector {
	return s.metrics
}
