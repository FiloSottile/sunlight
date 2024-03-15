package ctlog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	awshttp "github.com/aws/smithy-go/transport/http"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type ETagBackend struct {
	client  *s3.Client
	bucket  string
	metrics []prometheus.Collector
	log     *slog.Logger
}

func NewETagBackend(ctx context.Context, region, bucket, endpoint string, l *slog.Logger) (*ETagBackend, error) {
	counter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "etag_requests_total",
			Help: "ETag-locked S3 HTTP requests performed, by method and response code.",
		},
		[]string{"method", "code"},
	)
	duration := prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "etag_request_duration_seconds",
			Help:       "ETag-locked S3 HTTP request latencies, by method and response code.",
			Objectives: map[float64]float64{0.5: 0.05, 0.75: 0.025, 0.9: 0.01, 0.99: 0.001},
			MaxAge:     1 * time.Minute,
			AgeBuckets: 6,
		},
		[]string{"method", "code"},
	)

	transport := http.RoundTripper(http.DefaultTransport.(*http.Transport).Clone())
	transport = promhttp.InstrumentRoundTripperCounter(counter, transport)
	transport = promhttp.InstrumentRoundTripperDuration(duration, transport)

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config for ETag backend: %w", err)
	}

	return &ETagBackend{
		client: s3.NewFromConfig(cfg, func(o *s3.Options) {
			o.Region = region
			if endpoint != "" {
				o.BaseEndpoint = aws.String(endpoint)
			}
			o.HTTPClient = &http.Client{Transport: transport}
			o.Retryer = retry.AddWithMaxBackoffDelay(retry.NewStandard(), 5*time.Millisecond)
		}),
		bucket:  bucket,
		metrics: []prometheus.Collector{counter, duration},
		log:     l,
	}, nil
}

var _ LockBackend = &ETagBackend{}

type eTagCheckpoint struct {
	key  string
	body []byte
	eTag string
}

func (c *eTagCheckpoint) Bytes() []byte { return c.body }

var _ LockedCheckpoint = &eTagCheckpoint{}

func (b *ETagBackend) Fetch(ctx context.Context, logID [sha256.Size]byte) (LockedCheckpoint, error) {
	key := fmt.Sprintf("%x", logID)
	out, err := b.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(b.bucket),
		Key:    aws.String(key),
	}, func(options *s3.Options) {
		options.APIOptions = append(options.APIOptions, awshttp.AddHeaderValue("Cache-Control", "no-cache"))
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %q from ETag backend: %w", key, err)
	}
	defer out.Body.Close()
	if out.ETag == nil {
		return nil, fmt.Errorf("no ETag in response for %q from ETag backend", key)
	}
	data, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read %q from ETag backend: %w", key, err)
	}
	return &eTagCheckpoint{key: key, body: data, eTag: *out.ETag}, nil
}

func (b *ETagBackend) Replace(ctx context.Context, old LockedCheckpoint, new []byte) (LockedCheckpoint, error) {
	o := old.(*eTagCheckpoint)
	out, err := b.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(b.bucket),
		Key:           aws.String(o.key),
		Body:          bytes.NewReader(new),
		ContentLength: aws.Int64(int64(len(new))),
		ContentType:   aws.String("text/plain; charset=utf-8"),
	}, func(options *s3.Options) {
		options.APIOptions = append(options.APIOptions, awshttp.AddHeaderValue("If-Match", o.eTag))
	})
	if err != nil {
		return nil, fmtErrorf("failed to upload to ETag backend %q with ETag %q: %w", o.key, o.eTag, err)
	}
	if out.ETag == nil {
		return nil, fmtErrorf("no ETag in response for %q from ETag backend", o.key)
	}
	return &eTagCheckpoint{key: o.key, body: new, eTag: *out.ETag}, nil
}

func (b *ETagBackend) Create(ctx context.Context, logID [sha256.Size]byte, new []byte) error {
	key := fmt.Sprintf("%x", logID)
	_, err := b.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(b.bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(new),
		ContentLength: aws.Int64(int64(len(new))),
		ContentType:   aws.String("text/plain; charset=utf-8"),
	}, func(options *s3.Options) {
		options.APIOptions = append(options.APIOptions, awshttp.AddHeaderValue("If-Match", ""))
	})
	if err != nil {
		return fmt.Errorf("failed to upload %q to ETag backend: %w", key, err)
	}
	return nil
}

func (b *ETagBackend) Metrics() []prometheus.Collector {
	return b.metrics
}
