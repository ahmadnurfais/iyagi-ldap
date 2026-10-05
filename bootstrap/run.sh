#!/usr/bin/env bash
set -euo pipefail

patched_script=$(mktemp)
trap 'rm -f "$patched_script"' EXIT

# v0.6.3 can briefly return a null user after an update. Treat that as no current
# memberships so the declarative group assignments can still be applied.
sed 's/\[ \.data\.user\.groups\[\]\.displayName \]/[ (.data.user.groups \/\/ [])[] | .displayName ]/' \
    /app/bootstrap.sh > "$patched_script"

bash "$patched_script"

admin_password=$(<"${LLDAP_ADMIN_PASSWORD_FILE}")
token=$(curl --fail --silent --show-error \
    --request POST \
    --url "${LLDAP_URL}/auth/simple/login" \
    --header 'Content-Type: application/json' \
    --data "$(jo -- username="${LLDAP_ADMIN_USERNAME}" password="${admin_password}")" |
    jq --exit-status --raw-output '.token | select(type == "string" and length > 0)')

groups=$(curl --fail --silent --show-error \
    --request POST \
    --url "${LLDAP_URL}/api/graphql" \
    --header "Authorization: Bearer ${token}" \
    --header 'Content-Type: application/json' \
    --data '{"query":"query { user(userId: \"iyagi_backend_lookup\") { groups { displayName } } }"}' |
    jq --exit-status --compact-output '[.data.user.groups[].displayName] | sort')

if [[ "$groups" != '["lldap_strict_readonly"]' ]]; then
    printf 'Lookup user group verification failed: %s\n' "$groups" >&2
    exit 1
fi

printf '%s\n' 'Verified iyagi_backend_lookup has only lldap_strict_readonly membership.'
