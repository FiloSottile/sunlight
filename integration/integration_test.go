//go:build integration

// This is an integration test suite for Sunlight.
//
// It requires a running Sunlight instance to test against, which can be run from
// the included `docker-compose.yml` configuration via `docker compose up` prior
// to running
package integration

import (
	"fmt"
	"testing"
)

// TestPlaceholder
func TestPlaceholder(t *testing.T) {
	fmt.Println("it works!")
}
