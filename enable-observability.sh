#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$root_dir"

if [[ ! -f .env ]]; then
    printf '%s\n' 'Missing .env. Run the LDAP setup first.' >&2
    exit 1
fi

set -a
# shellcheck disable=SC1091
source .env
set +a

if [[ -z ${LOKI_WRITE_URL:-} || -z ${LOKI_INGEST_USERNAME:-} ]]; then
    printf '%s\n' 'Set LOKI_WRITE_URL and LOKI_INGEST_USERNAME in .env before enabling observability.' >&2
    exit 1
fi

mkdir -p secrets alloy-data
chmod 700 secrets

if [[ ! -s secrets/loki-ingest-token ]]; then
    printf '%s\n' 'Missing secrets/loki-ingest-token. Copy the matching credential from the Loki server.' >&2
    exit 1
fi

chmod 600 secrets/loki-ingest-token
docker compose --profile observability up -d alloy

printf '%s\n' 'Alloy log shipping is running.'
