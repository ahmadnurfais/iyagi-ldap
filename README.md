# Iyagi LLDAP

Standalone LLDAP directory for Iyagi staff authentication. The backend remains a separate
service and connects as the dedicated read-only lookup user over LDAPS.

## Setup

Requirements: Docker Engine with Compose v2, Bash, and OpenSSL. The pinned LLDAP v0.6.3 digest is
the same amd64 image used by the reference deployment.

```sh
cp .env.example .env
nano .env
./init-lldap.sh
docker compose --profile bootstrap run --rm bootstrap
```

`init-lldap.sh` creates a private CA and server certificate, generates all credentials under the
ignored `secrets/` directory, creates the shared Docker network when absent, and starts LLDAP. It
does not replace existing secret files or certificates. Bootstrap is a required, explicit deploy
step. It creates the lookup identity and application groups, reconciles the lookup identity to its
single declared group, and ends by verifying that exact membership.

The defaults expose LDAPS at `ldaps://localhost:16360` and the administration UI at
`http://localhost:17170`. Both bind to loopback. `LLDAP_HTTP_BIND_ADDRESS` and
`LLDAP_LDAPS_BIND_ADDRESS` control host publication independently. Keep the HTTP bind on loopback.
Set the LDAPS bind to a specific private host IP only when host-level private-network access is
required. Do not set either bind to `0.0.0.0` on an Internet-facing host. Plain LDAP port 3890 is
available only inside the shared Docker network and is not published.

`LLDAP_CERT_DNS_NAMES` and `LLDAP_CERT_IP_ADDRESSES` are comma-separated certificate SAN lists. The
defaults cover `lldap.iyagi.internal`, `localhost`, and `127.0.0.1`. Set them before first
initialization to every name or address used by clients. Initialization rejects partial CA or server
keypairs. It also refuses to generate missing secrets when an existing data volume is detected.

The LLDAP container joins the external `${LLDAP_NETWORK_NAME}` network, which defaults to
`iyagi-directory`, with alias `lldap.iyagi.internal`. Attach the backend container to the same
external network. The init script creates this network if absent. Host publication remains
available for clients that do not share the network. `LLDAP_CONTAINER_NAME` and
`LLDAP_DATA_VOLUME_NAME` default to `iyagi-lldap` and `iyagi-lldap-data`; keep the data volume name
stable across redeployments.

Only `certs/lldap-server.crt` and `certs/lldap-server.key` are mounted into LLDAP. The server files
are owned by UID/GID 1000 so the image's runtime user can read them. `certs/ca.key` remains host-only
with mode `0600`; clients receive only `certs/ca.crt`.

## Directory Layout

| Entry | Purpose |
| --- | --- |
| `dc=iyagi,dc=org` | Base DN |
| `ou=people,dc=iyagi,dc=org` | Standard LLDAP user container |
| `ou=groups,dc=iyagi,dc=org` | Standard LLDAP group container |
| `uid=iyagi_backend_lookup,ou=people,dc=iyagi,dc=org` | Backend search and bind account |

The backend lookup account belongs only to LLDAP's built-in `lldap_strict_readonly` group. Its
password is stored in `secrets/backend-lookup-password` and must not be used as an application user
credential.

## Group Conventions

| Group | Meaning |
| --- | --- |
| `service_admin-panel` | Identity may sign in to the Iyagi admin panel |
| `role_superadmin` | Iyagi superadmin role mapping |
| `role_editor` | Iyagi editor role mapping |
| `role_content-partner` | Iyagi content partner role mapping |
| `organization_internal-iyagi` | Identity belongs to the internal Iyagi organization |

Prefixes keep each concern explicit: `service_` controls service access, `role_` maps an Iyagi
application role, and `organization_` records organization membership. LDAP carries identity and
group membership only. Application permissions and authorization rules remain in the backend.
No custom LLDAP identity attributes are provisioned.

## User Assignment

Create staff identities and assign groups in the LLDAP UI:

1. Open `http://localhost:17170` and sign in as `admin` with the value in
   `secrets/lldap-admin-password`.
2. Open **Users**, create the identity, and set its standard name and email fields.
3. Open the user's **Groups** section.
4. Add `service_admin-panel` and `organization_internal-iyagi` for internal admin-panel users.
5. Add exactly the approved `role_superadmin`, `role_editor`, or `role_content-partner` groups.
6. Keep service and role groups off `iyagi_backend_lookup`; it requires only
   `lldap_strict_readonly`.

User and group deletion cleanup is disabled. Membership cleanup applies only to users declared in
`bootstrap/user-configs`, currently `iyagi_backend_lookup`. This keeps the lookup identity strictly
read-only without changing UI-managed staff memberships. Run bootstrap after every deployment:

```sh
docker compose --profile bootstrap run --rm bootstrap
```

Successful output ends with:

```text
Verified iyagi_backend_lookup has only lldap_strict_readonly membership.
```

## API Environment

Use the environment names supported by the separately deployed backend:

```dotenv
ADMIN_LDAP_URL=ldaps://lldap.iyagi.internal:6360
ADMIN_LDAP_BASE_DN=dc=iyagi,dc=org
ADMIN_LDAP_BIND_DN=uid=iyagi_backend_lookup,ou=people,dc=iyagi,dc=org
ADMIN_LDAP_BIND_PASSWORD_FILE=/run/secrets/backend-lookup-password
ADMIN_LDAP_CA_FILE=/run/certs/iyagi-lldap-ca.crt
ADMIN_LDAP_TLS_REJECT_UNAUTHORIZED=true
ADMIN_LDAP_TIMEOUT_MS=5000
```

For a backend running directly on the Docker host, use the published LDAPS port from `.env`, such
as `ldaps://localhost:16360`. Mount `certs/ca.crt` as `ADMIN_LDAP_CA_FILE`. Certificate verification
must remain enabled. `ADMIN_LDAP_BIND_PASSWORD` remains available for environments that inject
secrets directly instead of mounting a file.

## Backup And Restore

The named volume `iyagi-lldap-data` stores the SQLite database and generated LLDAP
configuration. Back up the volume together with `certs/` and `secrets/`. The key seed encrypts
stored passwords, so a database backup without its matching `secrets/lldap-key-seed` cannot be
fully restored.

Stop writes before creating a consistent archive:

```sh
mkdir -p backups
docker compose stop lldap
docker run --rm -v iyagi-lldap-data:/source:ro -v "$PWD/backups:/backup" alpine \
  tar -czf /backup/lldap-data.tar.gz -C /source .
tar -czf backups/lldap-files.tar.gz certs secrets .env
docker compose start lldap
```

Restore into an empty volume, then restore the matching certificate and secret archive:

```sh
docker compose down
docker volume create iyagi-lldap-data
docker run --rm -v iyagi-lldap-data:/target -v "$PWD/backups:/backup:ro" alpine \
  sh -c 'rm -rf /target/* && tar -xzf /backup/lldap-data.tar.gz -C /target'
tar -xzf backups/lldap-files.tar.gz
docker compose up -d --wait lldap
```

Protect backup archives as credentials. Test restoration periodically on an isolated host.

## Production Database

SQLite is suitable for a small standalone deployment. Production environments that require higher
availability, external database backups, or multiple operational tools should use PostgreSQL via
`LLDAP_DATABASE_URL`. Store the database password in the deployment secret system, restrict network
access to PostgreSQL, and back up PostgreSQL together with the LLDAP key seed and certificates.
