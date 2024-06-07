<p align="center">
    <picture>
        <source media="(prefers-color-scheme: dark)" srcset="https://github.com/C2SP/C2SP/assets/1225294/0cd04af2-e84d-4f48-b42e-ed430354e563">
        <source media="(prefers-color-scheme: light)" srcset="https://github.com/C2SP/C2SP/assets/1225294/0f239db0-7100-4bba-8608-bd4dc4134409">
        <img alt="The Sunlight logo, a bench under a tree in stylized black ink, cast against a large yellow sun, with the text Sunlight underneath" width="250" src="https://github.com/C2SP/C2SP/assets/1225294/0f239db0-7100-4bba-8608-bd4dc4134409">
    </picture>
</p>

Sunlight is a Certificate Transparency log implementation and monitoring API
designed for scalability, ease of operation, and reduced cost.

Additional resources, including test logs, a formal specification of the
monitoring API, and a comprehensive design document which explores the
motivating tradeoffs are available at [sunlight.dev](https://sunlight.dev).

Sunlight is based on the original Certificate Transparency design, on the Go
Checksum Database developed with Russ Cox, and on the feedback of many
individuals in the WebPKI community, and in particular of the Sigsum, Google
TrustFabric, and ISRG teams. Sunlight's development was sponsored by Let's
Encrypt.

## Operating a Sunlight log

A Sunlight instance is a single Go process, serving one or more CT logs,
configured with a YAML file. Config options are documented in detail [on the
Config struct][Config].

[Config]: https://github.com/search?q=repo%3AFiloSottile%2Fsunlight+symbol%3AConfig+path%3Acmd%2Fsunlight&type=code

There are three data storage locations with different properties involved in
operating a Sunlight instance:

  * A global "lock backend" which provides a compare-and-swap primitive, where only
    the signed tree head of each log is stored, to prevent accidental operational
    mistakes such as running two Sunlight instances against the same
    configuration from causing a fatal log split.

    This backend will always store trivial amounts of data, but it's important
    that a single global table/bucket/location is used.

    Currently, DynamoDB, Tigris (S3-like API with ETag support), and local
    SQLite are supported.

  * A per-log object store bucket, where the public tiles, checkpoints, and
    issuers are uploaded. Monitors can fetch the tree contents directly
    from these buckets.

    You should account for between 5GB and 10GB per million certificates, or
    between 5TB and 10TB for a six months shard at current (~75/s) submission
    rates.

    We recommend enabling S3 Object Versioning (see
    [#11](https://github.com/FiloSottile/sunlight/issues/11)) or overwriting
    protection (automatically enabled client-side on Tigris).

    Currently, S3 and S3-compatible APIs are supported.

  * A per-log deduplication cache, to return existing SCTs for previously
    submitted (pre-)certificates.

    Note that this can be a best-effort lookup, and it's ok to rollback a few
    entries on a regular basis, or even lose the cache in an emergency. The only
    consequence is that existing entries might be resubmitted, growing the size
    of the log.

    You should account for approximately 50MB per million certificates, or
    approximately 50GB for a six months shard at current (~75/s) submission
    rates.

    This is a local SQLite database, and it's designed to be backed up with
    Litestream.

Prometheus metrics are exposed *publicly* at `/metrics`. Logs are written to
stderr in human-readable format, and to stdout in JSON format.

A private HTTP debug server is also started on a random port on localhost. It
serves the net/http/pprof endpoints, as well as `/debug/logson` and
`/debug/logsoff` which enable and disable debug logging, respectively.

## The Rome prototype logs

The `rome/` folder contains the configuration for the Rome prototype logs,
deployed on Fly.io and Tigris from the main branch by GitHub Actions.

To deploy manually, run

    fly -c rome/fly.toml deploy
