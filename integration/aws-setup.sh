#!/bin/sh

set -xeuo pipefail

# This script conditionally creates an S3 bucket and DynamoDB table for
# the sunlight integration tests to use

export AWS_REGION=localhost
export AWS_ACCESS_KEY_ID=minioadmin
export AWS_SECRET_ACCESS_KEY=minioadmin

aws s3api head-bucket --bucket sunlight-integration --endpoint-url http://minio:9000 || \
  aws s3api create-bucket --bucket sunlight-integration --endpoint-url http://minio:9000

aws dynamodb describe-table --table-name sunlight-integration --endpoint-url http://dynamo:8000 || \
  aws dynamodb create-table --endpoint-url http://dynamo:8000 \
    --table-name sunlight-integration \
    --attribute-definitions AttributeName=logID,AttributeType=B \
    --key-schema AttributeName=logID,KeyType=HASH \
    --provisioned-throughput ReadCapacityUnits=1,WriteCapacityUnits=1
