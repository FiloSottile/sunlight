<p align="center">
    <picture>
        <source media="(prefers-color-scheme: dark)" srcset="https://github.com/C2SP/C2SP/assets/1225294/0cd04af2-e84d-4f48-b42e-ed430354e563">
        <source media="(prefers-color-scheme: light)" srcset="https://github.com/C2SP/C2SP/assets/1225294/0f239db0-7100-4bba-8608-bd4dc4134409">
        <img alt="The Sunlight logo, a bench under a tree in stylized black ink, cast against a large yellow sun, with the text Sunlight underneath" width="250" src="https://github.com/C2SP/C2SP/assets/1225294/0f239db0-7100-4bba-8608-bd4dc4134409">
    </picture>
</p>

Sunlight is a production-ready [Static Certificate Transparency][] log
implementation designed for scalability, ease of operation, and reduced cost.

[Static Certificate Transparency]: https://c2sp.org/static-ct-api

Additional resources, including test logs, a formal specification of the
monitoring API, and a comprehensive design document which explores the
motivating tradeoffs are available at [sunlight.dev](https://sunlight.dev).

Sunlight's development was sponsored by Let's Encrypt.

## Operating a Sunlight log

```
go install filippo.io/sunlight/cmd/...@latest
sunlight -c sunlight.yaml
```

All configuration is provided in a YAML file.

The full docs for the configuration file are on the [Config and LogConfig types](https://github.com/search?q=repo%3AFiloSottile%2Fsunlight+symbol%3AConfig+path%3Acmd%2Fsunlight&type=code), but this README presents all the options you need in common settings.

You can also browse [the *live configuration*](https://config.sunlight.geomys.org/) of the [production Tuscolo instance](https://groups.google.com/a/chromium.org/g/ct-policy/c/KCzYEIIZSxg), which includes systemd units for all services.

### Global configuration

```yaml
listen:
  - ":443"
acme:
  cache: /var/db/sunlight/autocert/
```

Sunlight listens on all the listed addresses (passed to [net.Listen](https://pkg.go.dev/net#Listen)), and automatically obtains TLS certificates for the logs hostnames via ACME.

```yaml
checkpoints: /tank/shared/checkpoints.db
```

Checkpoints is the path to an SQLite file that acts as the global lock backend, storing the latest checkpoint for each log, with compare-and-swap semantics. This database will always be very small.

This database must be global and it **must never be changed or modified** as an extra safety measure: it ensures that logs won't encounter a fatal split even due to accidental operational mistakes such as running two Sunlight instances against the same configuration.

The database must already exist, to prevent misconfigurations. Create it with 

```
sqlite3 checkpoints.db "CREATE TABLE checkpoints (logID BLOB PRIMARY KEY, body TEXT)"
```

Sunlight can alternatively use DynamoDB or S3-compatible object storage with `ETag` and `If-Match` support (such as Tigris) as global lock backends.

### Per-log configuration

Sunlight instances are multi-tenant: a single process hosts multiple logs, usually different *time shards* of the same log series.

```yaml
logs:
  - shortname: example2025h2
    notafterstart: 2025-07-01T00:00:00Z
    notafterlimit: 2026-01-01T00:00:00Z
```

Certificate Transparency logs are append-only, so to prevent them from growing unboundedly they are *temporally sharded* by certificate expiration time (the NotAfter X.509 field). You should generally run six month shards, i.e. one log for the first half of 2026, one for the second half, one for the first half of 2027, and so on. You should set up shards for the current year and the following two (e.g. 2025h1–2027h2 if setting up in 2025).

```yaml
    inception: 2025-04-25
```

The inception date is the only date on which Sunlight will create the log if it doesn’t exist yet, again to prevent misconfigurations.

```yaml
    submissionprefix: https://sunlight.example.org/example2025h2
    monitoringprefix: https://static.example.org/example2025h2
```

The submission prefix is the path at which Sunlight will serve this log.

The monitoring prefix is where the read path (see below) is available. Sunlight expects the files uploaded to the storage backend to become available at this path, but it doesn’t serve them itself!

```yaml
    secret: /tank/enc/example2025h2.seed.bin
```

Secret is the path to a file containing a secret seed from which the log's private keys are derived. This is the most important secret of the log!

To generate a new secret, run

```
sunlight-keygen -f example2025h2.seed.bin
```

```yaml
    period: 200
    poolsize: 750
```

The period is how often pending certificates are pooled and written to the storage backend, in milliseconds. The pool size is how many certificates can fit in the pool before new submissions are rejected until the next write.

A shorter period reduces latency, but causes more frequent writes. You should not set period any higher than 1000.

The pool size effectively acts as a rate limit: Sunlight will accept at most `poolsize / period` submissions.

```yaml
    cache: /tank/logs/example2025h2/cache.db
```

Cache is the path to an SQLite database that keeps track of submitted certificates to avoid duplicate entries. This part of Sunlight can tolerate data loss: it's ok to rollback a few entries on a regular basis, or even lose the cache in an emergency. The only consequence is that existing entries might be resubmitted, growing the size of the log. If the actual log data is hosted on object storage (see below) and the secret is backed up, a log can recover from the complete loss of the Sunlight server.

This generally doesn’t grow beyond 100 GB.

```yaml
    localdirectory: /tank/logs/example2025h2/data
```

or

```yaml
    s3region: atlantis-1
    s3bucket: example2025h2
    s3endpoint: https://data.example/s3/
```

There are two options for storing the actual Static CT assets: a regular POSIX filesystem (to which Sunlight issues fsync syscalls to ensure durability), or an S3-compatible object storage (which can be eventually consistent but must guarantee durability after a successful PUT). Remember that this storage backend must never lose writes or be rolled back.

Each six-months shard will reach approximately 1.5 TB at current rates. It starts growing sharply 90 days *before* its `notafterstart` date, and slows down 90 days before its `notafterlimit` date. It can be deleted [a couple months after](https://groups.google.com/a/chromium.org/g/ct-policy/c/rWNwrxokqZ8/m/6I_Be8x6AQAJ) its `notafterlimit` date.

You should consider a separate ZFS dataset or object storage bucket for each log, to make it easier to delete it once the log is retired. See, for example, [the Tuscolo ZFS configuration](https://gist.github.com/FiloSottile/989338e6ba8e03f2c699590ce83f537b). However, note that using separate AWS S3 buckets can cause [dynamic scaling issues when traffic moves naturally from one to another](https://groups.google.com/a/chromium.org/g/ct-policy/c/0R43Z58JuzA/m/raeusYYqAAAJ), so you should use a single bucket and delete logs with lifecycle rules if hosting on AWS S3.

### Monitoring and logging

JSON structured logs are produced on standard output, and human-readable logs are produced to standard error.

Numerous Prometheus metrics are exposed *publicly* at `/metrics`. (All hostnames serve all metrics, not just the ones of that log, if different logs have different hostnames.)

A *private* HTTP server listens on a random port of localhost, exposing the [net/http/pprof](https://pkg.go.dev/net/http/pprof) endpoints, as well as the following.

```
GET /debug/heavyhitter/useragents
GET /debug/heavyhitter/ips
```

The 100 most common client IP addresses and User-Agents, tracked with the Space-Saving algorithm.

```
POST /debug/keylog/on
POST /debug/keylog/off
```

Toggles for SSLKEYLOG. When `/debug/keylog/on` is called, KeyLogWriter starts writing to a new temp file. When `/debug/keylog/off` is called, KeyLogWriter stops writing to the temp file and closes it. If `/debug/keylog/off` is not called, the temp file is closed after 15 minutes of inactivity.

```
POST /debug/logs/on
POST /debug/logs/off
```

Toggles for debug logging.

You can use [the Tuscolo debug script](https://config.sunlight.geomys.org/#%2fusr%2flocal%2fbin%2fdebug) to automatically obtain the random port for a systemd service and invoke an endpoint.

```
debug [-u unit] {useragents|ips|keylog={on|off}|logs={on|off}|port}
```

### Partial tile garbage collection

Static CT chunks the log into “tiles” of 256 entries. If the pool is flushed and the final tiles is smaller than 256 entries, it’s written out as a partial tile. It is allowed to delete partial tiles once the corresponding full tile has been created.

partial-aftersun is a command designed to run as a cronjob which deletes superfluous partial tiles from a local storage backend, freeing up space. It reads the Sunlight config file directly, and has a number of safety measures to avoid deleting the wrong tiles.

The Tuscolo public configs include [an example of how to schedule it with systemd timers](https://config.sunlight.geomys.org/#%2fetc%2fsystemd%2fsystem%2fpartial-aftersun.service).

### Hosting the read path

The [Static CT monitoring API](https://github.com/C2SP/C2SP/blob/static-ct-api/v1.0.0/static-ct-api.md#monitoring-apis) can be implemented by simply serving the files uploaded to or stored in the storage backend by Sunlight.

If you’re using the S3 backend, that probably means simply placing a CDN in front of it, or making the bucket public. The monitoring prefix of the log can be completely different from the submission prefix, so you can point the read path directly at your static file serving infrastructure.

If you’re using the local filesystem backend, you could use any HTTP server, like nginx or Caddy. However, Sunlight provides a specialized HTTP file server with a number of Static CT friendly features.

- [Its configuration](https://github.com/search?q=repo%3AFiloSottile%2Fsunlight+symbol%3AConfig+path%3Acmd%2Fskylight&type=code) is nearly a subset of Sunlight’s.
- It automatically rate-limits clients that don’t provide a contact through the User-Agent, to make it easier to report client issues and to reduce the impact of non-malicious misbehaving clients.
- It provides the same monitoring and logging capabilities as Sunlight, including the same debug endpoints and copious public metrics.
- It exposes a `/health` endpoint which only returns 200 OK if all logs have produced validly-signed checkpoints in the last five seconds. This is what powers the Tuscolo [status page](https://status.sunlight.geomys.org/).

If using a different HTTP server, you should take care of setting the right `Content-Type`, `Content-Encoding`, `Cache-Control`, and ideally `Access-Control-Allow-Origin` headers. Feel free to inquire on the \#sunlight channel of the [transparency.dev Slack][] for help configuring other Static CT read path servers.

[transparency.dev Slack]: https://join.slack.com/t/transparency-dev/shared_invite/zt-27pkqo21d-okUFhur7YZ0rFoJVIOPznQ

You should expect more load on the read path than on the write path, as each certificate is generally only submitted once (or twice counting pre-certificates) but is fetched by many monitors. Be mindful of traffic charges if you run in the cloud! All assets except `/checkpoint` are immutable, so they are highly cacheable.
