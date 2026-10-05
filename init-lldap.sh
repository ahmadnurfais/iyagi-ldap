#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$root_dir"

if [[ ! -f .env ]]; then
    cp .env.example .env
    printf '%s\n' 'Created .env from .env.example. Review its bind address and ports, then run this script again.' >&2
    exit 1
fi

set -a
# shellcheck disable=SC1091
source .env
set +a

for command_name in docker openssl; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        printf 'Required command not found: %s\n' "$command_name" >&2
        exit 1
    fi
done

assert_complete_pair() {
    local first=$1
    local second=$2

    if [[ -e "$first" && ! -e "$second" ]] || [[ ! -e "$first" && -e "$second" ]]; then
        printf 'Incomplete keypair: %s and %s must both exist or both be absent.\n' "$first" "$second" >&2
        exit 1
    fi
}

assert_complete_pair certs/ca.crt certs/ca.key
assert_complete_pair certs/lldap-server.crt certs/lldap-server.key

if [[ -e certs/lldap-server.crt && ! -e certs/ca.crt ]]; then
    printf '%s\n' 'Refusing to create a new CA for an existing server certificate. Restore the matching CA.' >&2
    exit 1
fi

existing_data=false
if [[ -d lldap-data && -n "$(ls -A lldap-data)" ]]; then
    existing_data=true
fi

required_secrets=(
    secrets/lldap-admin-password
    secrets/lldap-jwt-secret
    secrets/lldap-key-seed
    secrets/backend-lookup-password
    secrets/audit-interceptor-password
    secrets/loki-ingest-token
)
if [[ "$existing_data" == true ]]; then
    for secret_path in "${required_secrets[@]}"; do
        if [[ ! -s "$secret_path" ]]; then
            printf 'Refusing to replace missing secret %s while existing LLDAP data is present. Restore it from backup.\n' \
                "$secret_path" >&2
            exit 1
        fi
    done
fi

mkdir -p certs secrets
chmod 700 certs secrets

if [[ ! -f certs/ca.crt || ! -f certs/ca.key ]]; then
    openssl req -x509 -newkey rsa:3072 -sha256 -days 3650 -nodes \
        -subj '/CN=Iyagi LLDAP CA' \
        -keyout certs/ca.key \
        -out certs/ca.crt
fi

if [[ ! -f certs/lldap-server.crt || ! -f certs/lldap-server.key ]]; then
    cert_dns_names=${LLDAP_CERT_DNS_NAMES:-lldap.iyagi.internal,localhost}
    cert_ip_addresses=${LLDAP_CERT_IP_ADDRESSES:-127.0.0.1}
    san_entries=()

    IFS=',' read -ra dns_names <<< "$cert_dns_names"
    for dns_name in "${dns_names[@]}"; do
        [[ -z "$dns_name" ]] && continue
        [[ "$dns_name" =~ ^[A-Za-z0-9.-]+$ ]] || {
            printf 'Invalid DNS SAN: %s\n' "$dns_name" >&2
            exit 1
        }
        san_entries+=("DNS:${dns_name}")
    done

    IFS=',' read -ra ip_addresses <<< "$cert_ip_addresses"
    for ip_address in "${ip_addresses[@]}"; do
        [[ -z "$ip_address" ]] && continue
        [[ "$ip_address" =~ ^[0-9A-Fa-f:.]+$ ]] || {
            printf 'Invalid IP SAN: %s\n' "$ip_address" >&2
            exit 1
        }
        san_entries+=("IP:${ip_address}")
    done

    if [[ ${#san_entries[@]} -eq 0 ]]; then
        printf '%s\n' 'At least one LLDAP_CERT_DNS_NAMES or LLDAP_CERT_IP_ADDRESSES entry is required.' >&2
        exit 1
    fi

    cert_common_name=${dns_names[0]:-${ip_addresses[0]}}
    san_value=$(IFS=,; printf '%s' "${san_entries[*]}")
    openssl req -newkey rsa:3072 -sha256 -nodes \
        -subj "/CN=${cert_common_name}" \
        -keyout certs/lldap-server.key \
        -out certs/lldap-server.csr

    openssl x509 -req -sha256 -days 825 \
        -in certs/lldap-server.csr \
        -CA certs/ca.crt \
        -CAkey certs/ca.key \
        -CAcreateserial \
        -extfile <(printf '%s\n' \
            "subjectAltName=${san_value}" \
            'extendedKeyUsage=serverAuth') \
        -out certs/lldap-server.crt
fi

generate_secret() {
    local path=$1
    local bytes=$2

    if [[ ! -f "$path" ]]; then
        openssl rand -base64 "$bytes" | tr -d '\n' > "$path"
    fi
}

generate_secret secrets/lldap-admin-password 32
generate_secret secrets/lldap-jwt-secret 32
generate_secret secrets/lldap-key-seed 32
generate_secret secrets/backend-lookup-password 32
generate_secret secrets/audit-interceptor-password 32
generate_secret secrets/loki-ingest-token 32

for secret_path in "${required_secrets[@]}"; do
    if [[ ! -s "$secret_path" ]]; then
        printf 'Secret is empty: %s\n' "$secret_path" >&2
        exit 1
    fi
done

chmod 600 certs/ca.key secrets/*
chown 1000:1000 certs/lldap-server.key certs/lldap-server.crt
chmod 600 certs/lldap-server.key
chmod 644 certs/ca.crt certs/lldap-server.crt
rm -f certs/lldap-server.csr certs/ca.srl

# LLDAP core secrets are read by the lldap container running as UID 1000 which
# matches the host owner, so 0600 is sufficient. The audit-interceptor runs as
# an in-image system user whose UID does not match the host; Docker file
# secrets preserve host ownership/mode, so its secret must be world-readable.
chmod 755 secrets
chmod 644 secrets/audit-interceptor-password secrets/loki-ingest-token

# Data dirs are host bind mounts under the project directory so backup, inspect,
# and migrate are trivial. UIDs for container processes:
#   lldap          : 1000:1000 (set via UID/GID env, matches host owner)
#   caddy          : root inside container, writes to /data, /config, /var/log/caddy
#   vector-agent   : root inside container, writes to /var/lib/vector
#   audit-interceptor: read_only root fs, no data dir
# Create the dirs and chown lldap-data to 1000:1000. The rest are initialized by
# their containers at first start; chowning here is a no-op after that.
mkdir -p lldap-data caddy-data caddy-config caddy-logs vector-data
chown -R 1000:1000 lldap-data

network_name=${LLDAP_NETWORK_NAME:-iyagi-directory}
if ! docker network inspect "$network_name" >/dev/null 2>&1; then
    docker network create "$network_name" >/dev/null
fi

grafana_ingress=${LLDAP_GRAFANA_INGRESS_NETWORK_NAME:-iyagi-grafana-ingress}
if ! docker network inspect "$grafana_ingress" >/dev/null 2>&1; then
    printf '%s\n' "Cross-project network '$grafana_ingress' not found. Run iyagi-grafana/init-grafana.sh first." >&2
    exit 1
fi

docker compose up -d --wait lldap audit-interceptor caddy vector-agent

printf '%s\n' 'LLDAP is running. Run the required bootstrap command from README.md, then verify it.'
