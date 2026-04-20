# go-auth

`go-auth` is a hosted authentication, authorization, TLS certificate, and LDAP management application.
It combines three subsystems in one server process:

- Auth management for local users, sessions, identity providers, and bearer tokens.
- Certificate management for storing and working with TLS certificate material.
- LDAP management for projecting users and groups into an LDAP directory.

It requires a PostgreSQL database for storage and can be configured
with environment variables and CLI flags.

## Quick Start

Run the container, in order to add users, groups, and scopes to the system:

```bash
export PG_URL='postgres://user@host.docker.internal/database?sslmode=prefer'
docker run --rm  --name go-auth \
  -e PG_URL -e PG_PASSWORD \
  -p 80:80 \
  ghcr.io/mutablelogic/go-auth run --no-auth.enabled --local.enabled
```

Then you can login with the local provider at `http://localhost:80` (to which you only need to add an email address) and start managing users, groups, and scopes. The local provider supports browser-based login flows but does not have a password-based API, so you must create users with the CLI or UI before you can authenticate.

After you've added the scopes, users and groups, you can enable authentication on the management endpoints and add more providers as needed. See the sections below for details on all available configuration options.

Notes:

- `PG_URL` is required. The service will not start without a PostgreSQL connection.

## Auth Parameters

These parameters configure the authentication manager and identity provider integration.

| Parameter | Type | Description |
| --- | --- | --- |
| `AUTH_SCHEMA` | env | Database schema used for auth tables. |
| `AUTH_SESSION_TTL` | env | Session lifetime. Defaults to 15 minutes when unset. |
| `AUTH_REFRESH_TTL` | env | Refresh token lifetime. Defaults to 7 days when unset. |
| `GOOGLE_CLIENT_ID` | env | Enables the Google provider when set. |
| `GOOGLE_CLIENT_SECRET` | env | Google OAuth client secret. |
| `--auth.enabled` / `--no-auth` | cli | Enable or disable authentication on management endpoints. Default is enabled. |
| `--auth.signer=file:///path/to/key.pem?kid=main` | cli | Add a private key PEM file used to sign issued tokens. Repeat to add multiple signers. |
| `--local.enabled` / `--no-local.enabled` | cli | Enable or disable the built-in local browser-flow identity provider. Default is disabled. |

Examples:

```bash
docker run --rm \
  -p 8084:80 \
  -e AUTHMANAGER_ADDR=:80 \
  -e PG_URL='postgres://user:password@host.docker.internal/authdb?sslmode=disable' \
  -e AUTH_SCHEMA='auth' \
  -e AUTH_SESSION_TTL='30m' \
  -e AUTH_REFRESH_TTL='168h' \
  -e GOOGLE_CLIENT_ID='your-google-client-id' \
  -e GOOGLE_CLIENT_SECRET='your-google-client-secret' \
  "$IMAGE"
```

## Cert Parameters

These parameters configure the certificate manager.

| Parameter | Type | Description |
| --- | --- | --- |
| `CERT_ENABLED` | env | Enable or disable the certificate manager. Default is `true`. |
| `CERT_PASSPHRASE` | env | Passphrase used for encrypting private keys. Can be supplied multiple times in CLI usage; in Docker this is typically provided once per environment variable name supported by your runtime. |
| `CERT_SCHEMA` | env | Database schema used for certificate tables. |

Example:

```bash
docker run --rm \
  -p 8084:80 \
  -e AUTHMANAGER_ADDR=:80 \
  -e PG_URL='postgres://user:password@host.docker.internal/authdb?sslmode=disable' \
  -e CERT_ENABLED='true' \
  -e CERT_SCHEMA='cert' \
  -e CERT_PASSPHRASE='change-me' \
  "$IMAGE"
```

## LDAP Parameters

These parameters configure the LDAP manager. The LDAP manager is only started when `LDAP_URL` is set.

| Parameter | Type | Description |
| --- | --- | --- |
| `LDAP_URL` | env | LDAP server URL to connect to or manage. When unset, the LDAP manager is disabled. |
| `LDAP_BASEDN` | env | Base DN for LDAP entries. Default is `dc=example,dc=org`. |
| `LDAP_USER` | env | Bind user DN used by the LDAP manager. Default is `cn=admin,dc=example,dc=org`. |
| `LDAP_PASS` | env | Bind password for the LDAP manager. |
| `LDAP_USER_DN` | env | Relative DN for the user subtree, for example `ou=users`. |
| `LDAP_GROUP_DN` | env | Relative DN for the group subtree, for example `ou=groups`. |

Example:

```bash
docker run --rm \
  -p 8084:80 \
  -e AUTHMANAGER_ADDR=:80 \
  -e PG_URL='postgres://user:password@host.docker.internal/authdb?sslmode=disable' \
  -e LDAP_URL='ldap://ldap.example.org:389' \
  -e LDAP_BASEDN='dc=example,dc=org' \
  -e LDAP_USER='cn=admin,dc=example,dc=org' \
  -e LDAP_PASS='change-me' \
  -e LDAP_USER_DN='ou=users' \
  -e LDAP_GROUP_DN='ou=groups' \
  "$IMAGE"
```

## Common Container Parameters

These are not subsystem-specific, but they are usually required in Docker deployments:

| Parameter | Type | Description |
| --- | --- | --- |
| `PG_URL` | env | PostgreSQL connection URL. Required for startup. |
| `PG_PASSWORD` | env | PostgreSQL password override. |
| `AUTHMANAGER_ADDR` | env | HTTP listen address. Set this to `:80` or `:443` in containers. |
| `ADDR` | env | Alternate generic listen-address environment variable. |
| `--http.prefix` | cli | HTTP API path prefix. Default is `/api`. |
| `--http.timeout` | cli | HTTP server read/write timeout. Default is `15m`. |
| `--http.origin` | cli | Cross-origin protection origin configuration. |
| `--tls.name` | cli | TLS server name. |
| `--tls.cert` | cli | TLS certificate file inside the container. |
| `--tls.key` | cli | TLS private key file inside the container. |
| `--ui` / `--no-ui` | cli | Enable or disable the embedded UI. Default is enabled. |
| `--openapi` / `--no-openapi` | cli | Enable or disable the OpenAPI endpoints. Default is enabled. |

If you mount certificate files into the container, a TLS-enabled run looks like this:

```bash
docker run --rm \
  -p 8443:443 \
  -e AUTHMANAGER_ADDR=:443 \
  -e PG_URL='postgres://user:password@host.docker.internal/authdb?sslmode=disable' \
  -v "$PWD/certs:/certs:ro" \
  "$IMAGE" \
  run --tls.cert=/certs/tls.crt --tls.key=/certs/tls.key
```
