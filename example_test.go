package sunlight_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"

	"filippo.io/sunlight"
)

func ExampleClient_Entries() {
	// Note: clients that don't participate in the transparency ecosystem
	// and are only interested in a feed of names can consider using the
	// more efficient UnauthenticatedTrimmedEntries method instead.

	block, _ := pem.Decode([]byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4i7AmqGoGHsorn/eyclTMjrAnM0J
UUbyGJUxXqq1AjQ4qBC77wXkWt7s/HA8An2vrEBKIGQzqTjV8QIHrmpd4w==
-----END PUBLIC KEY-----`))
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	client, err := sunlight.NewClient(&sunlight.ClientConfig{
		MonitoringPrefix: "https://navigli2025h2.skylight.geomys.org/",
		PublicKey:        key,
		UserAgent:        "ExampleClient (changeme@example.com, +https://example.com)",
	})
	if err != nil {
		panic(err)
	}

	var start int64
	for {
		checkpoint, _, err := client.Checkpoint(context.TODO())
		if err != nil {
			panic(err)
		}
		for i, entry := range client.Entries(context.TODO(), checkpoint.Tree, start) {
			fmt.Printf("%d: %d %d %x\n", i, entry.LeafIndex, entry.Timestamp, entry.IssuerKeyHash)
			start = i + 1
		}
		if err := client.Err(); err != nil {
			panic(err)
		}
	}
}

func ExampleClient_UnauthenticatedTrimmedEntries() {
	// Important: UnauthenticatedTrimmedEntries does NOT verify the signed tree
	// head. It is only suitable for clients that don't participate in the
	// transparency ecosystem, and are only interested in a feed of names.

	client, err := sunlight.NewClient(&sunlight.ClientConfig{
		MonitoringPrefix: "https://navigli2025h2.skylight.geomys.org/",
		UserAgent:        "ExampleClient (changeme@example.com, +https://example.com)",
	})
	if err != nil {
		panic(err)
	}

	var start int64
	for {
		checkpoint, err := client.Fetcher().ReadEndpoint(context.TODO(), "checkpoint")
		if err != nil {
			panic(err)
		}

		_, rest, _ := strings.Cut(string(checkpoint), "\n")
		size, _, _ := strings.Cut(rest, "\n")
		end, err := strconv.ParseInt(size, 10, 64)
		if err != nil {
			panic(err)
		}

		for i, entry := range client.UnauthenticatedTrimmedEntries(context.TODO(), start, end) {
			fmt.Printf("%d: %s\n", i, entry.DNS)
			start = i + 1
		}
		if err := client.Err(); err != nil {
			panic(err)
		}
	}
}

func ExampleClient_localFilesystem() {
	block, _ := pem.Decode([]byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4i7AmqGoGHsorn/eyclTMjrAnM0J
UUbyGJUxXqq1AjQ4qBC77wXkWt7s/HA8An2vrEBKIGQzqTjV8QIHrmpd4w==
-----END PUBLIC KEY-----`))
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	client, err := sunlight.NewClient(&sunlight.ClientConfig{
		MonitoringPrefix: "gzip+file:///tank/logs/navigli2025h2/data/",
		PublicKey:        key,
	})
	if err != nil {
		panic(err)
	}

	checkpoint, _, err := client.Checkpoint(context.TODO())
	if err != nil {
		panic(err)
	}
	entry, _, err := client.Entry(context.TODO(), checkpoint.Tree, 142424242)
	if err != nil {
		panic(err)
	}
	println(entry.Timestamp)
}
