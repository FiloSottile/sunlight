package ctlog

import (
	"bytes"
	"context"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type S3Backend struct {
	client *s3.Client
	bucket string
}

func NewS3Backend(ctx context.Context, region, bucket string) (*S3Backend, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, err
	}

	return &S3Backend{
		client: s3.NewFromConfig(cfg),
		bucket: bucket,
	}, nil
}

var _ Backend = &S3Backend{}

func (s *S3Backend) Upload(ctx context.Context, key string, data []byte) error {
	// TODO: give up on slow requests and retry.
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(data),
	})
	return err
}

func (s *S3Backend) Fetch(ctx context.Context, key string) ([]byte, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}
	defer out.Body.Close()
	return io.ReadAll(out.Body)
}
