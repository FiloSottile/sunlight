package ctlog

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type DynamoDBBackend struct {
	client  *dynamodb.Client
	table   string
	metrics []prometheus.Collector
	log     *slog.Logger
}

func NewDynamoDBBackend(ctx context.Context, region, table string, l *slog.Logger) (*DynamoDBBackend, error) {
	counter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dynamodb_requests_total",
			Help: "DynamoDB requests performed, by method and response code.",
		},
		[]string{"method", "code"},
	)
	duration := prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "dynamodb_request_duration_seconds",
			Help:       "DynamoDB request latencies, by method and response code.",
			Objectives: map[float64]float64{0.5: 0.05, 0.75: 0.025, 0.9: 0.01, 0.99: 0.001},
			MaxAge:     1 * time.Minute,
			AgeBuckets: 6,
		},
		[]string{"method", "code"},
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
		return nil, fmt.Errorf("failed to load AWS config for DynamoDB backend: %w", err)
	}

	return &DynamoDBBackend{
		client:  dynamodb.NewFromConfig(cfg),
		table:   table,
		metrics: []prometheus.Collector{counter, duration},
		log:     l,
	}, nil
}

var _ LockBackend = &DynamoDBBackend{}

type dynamoDBCheckpoint struct {
	body  []byte
	logID [sha256.Size]byte
}

func (c *dynamoDBCheckpoint) Bytes() []byte { return c.body }

var _ LockedCheckpoint = &dynamoDBCheckpoint{}

func (b *DynamoDBBackend) Fetch(ctx context.Context, logID [sha256.Size]byte) (LockedCheckpoint, error) {
	resp, err := b.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(b.table),
		Key: map[string]types.AttributeValue{
			"logID": &types.AttributeValueMemberB{Value: logID[:]},
		},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, err
	}
	if resp.Item == nil {
		return nil, errors.New("checkpoint not found")
	}
	return &dynamoDBCheckpoint{logID: logID,
		body: resp.Item["checkpoint"].(*types.AttributeValueMemberB).Value}, nil
}

func (b *DynamoDBBackend) Replace(ctx context.Context, old LockedCheckpoint, new []byte) (LockedCheckpoint, error) {
	o := old.(*dynamoDBCheckpoint)
	_, err := b.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(b.table),
		Item: map[string]types.AttributeValue{
			"logID":      &types.AttributeValueMemberB{Value: o.logID[:]},
			"checkpoint": &types.AttributeValueMemberB{Value: new},
		},
		ConditionExpression: aws.String("checkpoint = :old"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":old": &types.AttributeValueMemberB{Value: o.body},
		},
	})
	if err != nil {
		return nil, err
	}
	return &dynamoDBCheckpoint{body: new, logID: o.logID}, nil
}

func (b *DynamoDBBackend) Create(ctx context.Context, logID [sha256.Size]byte, new []byte) error {
	_, err := b.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(b.table),
		Item: map[string]types.AttributeValue{
			"logID":      &types.AttributeValueMemberB{Value: logID[:]},
			"checkpoint": &types.AttributeValueMemberB{Value: new},
		},
		ConditionExpression: aws.String("attribute_not_exists(logID)"),
	})
	return err
}

func (b *DynamoDBBackend) Metrics() []prometheus.Collector {
	return b.metrics
}
