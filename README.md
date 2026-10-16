# Iyagi LLDAP

Directory service for Iyagi staff authentication and group membership.

## Components

| Component | Purpose |
| --- | --- |
| LLDAP | Stores identities, credentials, and groups |
| LLDAP admin audit proxy | Serves the admin UI and records HTTP administration activity |
| LDAPS gateway | Exposes only LDAPS to application containers |
| Bootstrap | Creates required service accounts and groups |

## Setup

Requirements: Docker Engine with Compose v2, Bash, and OpenSSL.

```sh
cp .env.example .env
nano .env
./init-lldap.sh
docker compose --profile bootstrap run --rm bootstrap
```

The initialization script creates the private CA, server certificate, secrets, data directories, and
Docker networks. It starts:

```text
iyagi-lldap
iyagi-lldap-admin-audit-proxy
iyagi-ldaps-gateway
```

Successful bootstrap ends with:

```text
Verified iyagi_backend_lookup has only lldap_strict_readonly membership.
```

## Admin Access

The admin audit proxy binds to:

```text
http://127.0.0.1:18443
```

For temporary access, create an SSH tunnel:

```sh
ssh -L 18443:127.0.0.1:18443 <ldap-host>
```

Open `http://127.0.0.1:18443` and sign in as `admin`. The generated password is stored in:

```text
secrets/lldap-admin-password
```

For public HTTPS access, configure the host reverse proxy to forward to `127.0.0.1:18443`. Examples
are available under `nginx/`. Do not proxy directly to LLDAP port `17170`; administrative traffic
must pass through the admin audit proxy.

## Application Connection

Attach application containers to the external Docker network:

```yaml
networks:
  iyagi-directory:
    external: true
    name: iyagi-directory
```

Use:

```dotenv
ADMIN_LDAP_URL=ldaps://lldap.iyagi.internal:6360
ADMIN_LDAP_BASE_DN=dc=iyagi,dc=org
ADMIN_LDAP_BIND_DN=uid=iyagi_backend_lookup,ou=people,dc=iyagi,dc=org
ADMIN_LDAP_BIND_PASSWORD_FILE=/run/secrets/backend-lookup-password
ADMIN_LDAP_CA_FILE=/run/certs/iyagi-lldap-ca.crt
ADMIN_LDAP_TLS_REJECT_UNAUTHORIZED=true
ADMIN_LDAP_TIMEOUT_MS=5000
```

Mount the lookup password and CA certificate into the application container:

```yaml
volumes:
  - /path/to/LDAP/secrets/backend-lookup-password:/run/secrets/backend-lookup-password:ro
  - /path/to/LDAP/certs/ca.crt:/run/certs/iyagi-lldap-ca.crt:ro
```

A service using host networking can connect to the published loopback port:

```dotenv
ADMIN_LDAP_URL=ldaps://127.0.0.1:16360
```

The backend lookup account belongs only to `lldap_strict_readonly`.

## Directory Structure

| Entry | Purpose |
| --- | --- |
| `dc=iyagi,dc=org` | Base DN |
| `ou=people,dc=iyagi,dc=org` | User entries |
| `ou=groups,dc=iyagi,dc=org` | Group entries |
| `uid=iyagi_backend_lookup,ou=people,dc=iyagi,dc=org` | Application lookup account |

## Groups

| Group | Meaning |
| --- | --- |
| `service_admin-panel` | May sign in to the Iyagi admin panel |
| `role_superadmin` | Superadmin role |
| `role_editor` | Editor role |
| `role_content-partner` | Content partner role |
| `organization_internal` | Iyagi internal organization |

Create staff users in the admin UI and assign the required service, role, and organization groups.
The application remains responsible for permission enforcement.

## Certificates

The setup creates:

```text
certs/ca.crt
certs/ca.key
certs/lldap-server.crt
certs/lldap-server.key
```

Clients trust `certs/ca.crt`. Keep `certs/ca.key` private. The default server certificate covers:

```text
lldap.iyagi.internal
localhost
127.0.0.1
```

Set `LLDAP_CERT_DNS_NAMES` and `LLDAP_CERT_IP_ADDRESSES` before first initialization when clients use
other names or addresses.

Verify LDAPS:

```sh
openssl s_client \
  -connect 127.0.0.1:16360 \
  -servername lldap.iyagi.internal \
  -CAfile certs/ca.crt \
  -verify_return_error </dev/null
```

Expected output includes:

```text
Verification: OK
Verify return code: 0 (ok)
```

## Audit Logs

The admin audit proxy writes structured administration events to its container logs. Events include
the administrator, affected user or group, result, client address, and available before/after data.
LDAP and LDAPS activity remains in the LLDAP container logs.

Log forwarding is optional and disabled by default. To enable the collector, configure the log
destination and source labels in `.env`, place its credential in `secrets/loki-ingest-token`, then
run:

```sh
./enable-observability.sh
```

The receiving endpoint is managed outside this repository.

## Backup And Restore

Back up these paths together:

```text
lldap-data/
certs/
secrets/
.env
```

The key seed in `secrets/lldap-key-seed` is required to restore encrypted password data.

Create a consistent backup:

```sh
mkdir -p backups
docker compose stop lldap
tar -czf backups/lldap-data.tar.gz -C lldap-data .
tar -czf backups/lldap-files.tar.gz certs secrets .env
docker compose start lldap
```

Restore into an empty data directory:

```sh
docker compose down
rm -rf lldap-data
mkdir lldap-data
tar -xzf backups/lldap-data.tar.gz -C lldap-data
tar -xzf backups/lldap-files.tar.gz
chown -R 1000:1000 lldap-data certs/lldap-server.crt certs/lldap-server.key secrets
docker compose up -d --build --wait
```

Protect backup archives as credentials and test restoration on an isolated host.
