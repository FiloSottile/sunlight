# The names tiles Static CT extension

Names tiles are an extension to the [Static CT][] monitoring API aimed at
clients that are not interested in the security properties of the Certificate
Transparency ecosystem, but only in a feed of certificate names.

> [!CAUTION]
> This API doesn't allow checking inclusion in RFC 6962 Signed Tree Heads, so it
> is only suitable for clients that already disregard those checks.

These clients can reduce the bandwidth burden on logs by fetching "names tiles"
which include all the names on logged certificates as easy-to-parse JSON lines.

The Go [Client.UnauthenticatedTrimmedEntries][] method automatically fetches
names tiles if available, and falls back to full Static CT data tiles otherwise.
Names are considered at "level -2" by the lower-level Go APIs.

## Names tiles

For every data tile (e.g. `/tile/data/x123/456`), logs that implement this
extension publish an equivalent names tile at

    <monitoring prefix>/tile/names/<N>[.p/<W>]

(e.g. `/tile/names/x123/456`) with `Content-Type: application/jsonl;
charset=utf-8` and `Content-Encoding: gzip`. Like data tiles, names tiles are
immutable.

The entries in a names tile correspond to the entries in the equivalent data
tile, but are encoded as newline-separated JSON objects, each encoding a
[TrimmedEntry][] structure.

In particular the JSON object include the certificate's Subject fields and DNS
and IP Subject Alternative Names.

```json
{
    "Timestamp": 1753375092043,
    "Subject": {
        "CommonName": "example.com"
    },
    "DNS": [
        "example.com",
        "www.example.com"
    ]
}
```

[Static CT]: https://c2sp.org/static-ct-api
[Client.UnauthenticatedTrimmedEntries]: https://filippo.io/sunlight.Client.UnauthenticatedTrimmedEntries
[TrimmedEntry]: https://filippo.io/sunlight.TrimmedEntry
