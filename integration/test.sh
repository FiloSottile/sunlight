#!/bin/bash
set -eu

stop() {
  ret=$?

  # Print the logs from each of the service containers.
  # This list needs to be kept in sync with ./integration/docker-compose.yml
  for ctr in minio dynamo aws-setup sunlight; do
    name="integration-$ctr-1"
    echo "::group::$name logs"
    docker logs -t "$name" || echo "no logs"
    echo "::endgroup::"
  done

  docker compose down

  exit $ret
}

trap stop EXIT

# Build containers:
echo "::group::docker compose build"
docker compose build
echo "::endgroup::"

# Start services in background
echo "::group::docker compose up"
docker compose up -d --wait
echo "::endgroup::"

# Run integration tests

echo "::group::Integration Test"
RET=$(go test -tags=integration)
if [ "$RET" != "0" ]; then
  echo "tests returned $RET"
  exit 1
fi
echo "Success"
echo "::endgroup::"
