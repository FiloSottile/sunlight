#!/bin/bash
set -xeuo pipefail

litestream restore -if-replica-exists -if-db-not-exists /var/db/sunlight/rome2024h1.db
litestream restore -if-replica-exists -if-db-not-exists /var/db/sunlight/rome2024h2.db
litestream restore -if-replica-exists -if-db-not-exists /var/db/sunlight/rome2025h1.db
exec litestream replicate -exec /usr/local/bin/sunlight > /var/db/sunlight/sunlight.log
