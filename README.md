# go-auth

A self-hosted authorization server written in Go, implementing the OAuth 2.0 authorization code flow with PKCE and OIDC-compatible discovery, JWKS, and userinfo endpoints. It issues self-contained, locally signed JWTs, supports multiple upstream identity providers, and ships with a WebAssembly admin UI for managing users, groups, and scopes.

> **Not production ready.** This project is under active development and has known gaps (see below). Do not use it to protect production systems.

## Motivation

`go-auth` is designed to be embedded directly into a larger Go service or run as a standalone server, depending on what a deployment needs. It gives you full control over user data, token policy, and provider configuration within the same operational footprint as the rest of your stack.

Key design goals:

- **Self-contained tokens.** Access tokens are RS256-signed JWTs with user and session claims embedded. Protected services validate tokens locally against the public key — no round-trip to the auth server on every request.
- **Provider abstraction.** Two identity providers are implemented: Google OAuth 2.0 and a built-in local browser flow (intended for development and debugging). The `Provider` interface makes it straightforward to add others (LDAP, SAML, certificate-based auth).
- **Single binary.** The server binary embeds the admin UI (WebAssembly + IBM Carbon) and bootstraps its own database schema on first run.
- **PostgreSQL-backed.** Sessions, users, groups, and identities live in PostgreSQL. `LISTEN/NOTIFY` streams table changes in real time.

Current known gaps:

- **Refresh tokens** are currently identical to access tokens; proper token separation is on the roadmap.
- **The admin UI** is incomplete — user and group management works but some views are not yet finished.
- **Scopes** are embedded in issued tokens but are not enforced by the authentication middleware; per-endpoint scope checks are not yet implemented.
- **Revoked tokens** are not cached. The auth middleware checks the session state embedded in the JWT at issuance, so a revoked token continues to be accepted until it expires. A revocation cache (populated via `LISTEN/NOTIFY`) is on the roadmap.

Roadmap:

- **Additional identity providers** — GitHub, Meta, Apple, and Amazon OAuth/OIDC flows, plus LDAP for corporate directory integration
- **TLS certificate management** — automatic certificate provisioning and renewal via ACME/Let's Encrypt and locally-generated authorities/certificates
- **Private key rotation** — scheduled RSA key rotation with a JWKS rollover period so existing tokens remain valid during the transition
- **Token revocation cache** — in-memory set of revoked session IDs kept in sync via PostgreSQL `LISTEN/NOTIFY`, checked by the auth middleware on every request

## Quick Start

### Prerequisites

- Go 1.25+
- Node.js + npm (for the frontend, if rebuilding)
- PostgreSQL 14+

### Build

```bash
# Build the server binary (includes the embedded WASM frontend)
make wasm
make cmd

# Or build everything from scratch including npm bundles
make clean && make wasm && make cmd
```

The binary is written to `build/authserver`.

### Run

```bash
build/authserver run \
  --pg.url="postgres://user:password@localhost/authdb" \
  --http.addr=":8080" \
  --local-provider \
  --no-auth
```

`--local-provider` enables the built-in local identity provider, which is intended for testing only — it accepts any email address without a password, and requires no client ID. Do not use it in production.

`--no-auth` disables the authentication middleware on the management API, which is necessary on first run before any users exist. Remove it once an admin user has been created.

With Google OAuth:

```bash
build/authserver run \
  --pg.url="postgres://user:password@localhost/authdb" \
  --http.addr=":8080" \
  --google.client-id=YOUR_CLIENT_ID \
  --google.client-secret=YOUR_CLIENT_SECRET
```

#### Getting a Google OAuth client ID

1. Go to the [Google Cloud Console](https://console.cloud.google.com/) and create or select a project.
2. Navigate to **APIs & Services → Credentials** and click **Create Credentials → OAuth client ID**.
3. If prompted, configure the OAuth consent screen first. Choose **Internal** if this is for users within your Google Workspace organisation, or **External** for any Google account. Fill in the app name and support email.
4. For application type, choose **Desktop app**.
5. Click **Create**. Copy the **Client ID** and **Client Secret** into `--google.client-id` and `--google.client-secret` (or the equivalent environment variables).

#### Server flags

| Flag | Environment variable | Description |
|---|---|---|
| `--pg.url` | `PG_URL` | PostgreSQL connection URL |
| `--pg.password` | `PG_PASSWORD` | PostgreSQL password (overrides URL) |
| `--http.addr` | `AUTHSERVER_ADDR`, `ADDR` | Listen address (default `localhost:8084`) |
| `--http.prefix` | | HTTP path prefix (default `/api`) |
| `--http.timeout` | | Server read/write timeout (default `15m`) |
| `--http.origin` | | CORS origin — empty for same-origin, `*` for all |
| `--tls.cert` | | TLS certificate file |
| `--tls.key` | | TLS key file |
| `--google.client-id` | `GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `--google.client-secret` | `GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `--otel.endpoint` | `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP collector endpoint |
| `--otel.header` | `OTEL_EXPORTER_OTLP_HEADERS` | OTLP collector headers |
| `--otel.name` | `OTEL_SERVICE_NAME` | Service name in traces (default `authserver`) |
| `--[no-]local-provider` | | Enable the local browser-flow identity provider |
| `--[no-]auth` | | Enable authentication on management endpoints (default on) |
| `--[no-]ui` | | Serve the embedded admin UI (default on) |
| `--[no-]openapi` | | Serve OpenAPI spec at `{prefix}/openapi.{json,yaml,html}` (default on) |

### CLI usage

The `authserver` binary doubles as a CLI client. Set `AUTHSERVER_ADDR` to the host and port of the running server so you don't need to repeat it on every command:

```bash
export AUTHSERVER_ADDR=localhost:8080
```

```bash
# Open the admin UI in a browser
authserver ui

# Browse the OpenAPI documentation
authserver openapi

# Output the OpenAPI spec
authserver openapi --json
authserver openapi --yaml

# List configured identity providers
authserver providers

# Log in via a provider (opens a browser window to complete the OAuth flow)
authserver login
authserver login google

# See all available commands and flags
authserver --help
```

After a successful `login`, the resulting token is stored locally and used automatically by subsequent commands that require authentication.


## Architecture

### Directory structure

| Path | Description |
|---|---|
| `cmd/authserver/` | Server binary — CLI flags, provider wiring, HTTP server setup |
| `pkg/manager/` | Core domain logic — users, groups, scopes, sessions, identities, token signing |
| `pkg/httphandler/auth/` | OIDC/OAuth endpoints — authorize, token exchange, revoke, userinfo, JWKS |
| `pkg/httphandler/manager/` | REST management API — CRUD for users, groups, scopes |
| `pkg/middleware/` | JWT authentication middleware — validates tokens and injects user/session into context |
| `pkg/provider/` | Identity provider interface and implementations (Google, local browser flow) |
| `pkg/oidc/` | OIDC/OAuth primitives — token signing, PKCE, authorization code flow helpers |
| `pkg/crypto/` | RSA key generation, PEM encoding/decoding |
| `schema/` | Database types, query builders, and JSON serialization |
| `wasm/frontend/` | WebAssembly admin UI (Go compiled to WASM, IBM Carbon design system) |
| `npm/carbon/` | esbuild bundle for Carbon web components |

### Component diagram

```mermaid
flowchart TD
    Browser["<b>Browser / Client</b>"]
    AdminUI["<b>Admin UI</b> (WASM + Carbon)"]
    AuthEP["<b>Auth Endpoints</b> (pkg/httphandler/auth)"]
    MgrEP["<b>Manager Endpoints</b> (pkg/httphandler/manager)"]
    Middleware["<b>Auth Middleware</b> (pkg/middleware)"]
    Manager["<b>Manager</b> (pkg/manager)"]
    OIDC["<b>OIDC Primitives</b> (pkg/oidc)"]
    Crypto["<b>Crypto</b> (pkg/crypto)"]
    Providers["<b>Providers</b> (pkg/provider)"]
    Google["<b>Google Provider</b>"]
    Local["<b>Local Provider</b>"]
    Schema["<b>Schema</b> (schema/)"]
    PG[("<b>PostgreSQL</b>")]

    Browser -->|"OAuth flow"| AuthEP
    Browser -->|"Admin API (Bearer token)"| Middleware
    AdminUI -->|"served by"| Browser
    Middleware --> MgrEP
    AuthEP --> Manager
    MgrEP --> Manager
    Manager --> OIDC
    Manager --> Crypto
    Manager --> Providers
    Manager --> Schema
    Providers --> Google
    Providers --> Local
    Schema --> PG
    OIDC --> Crypto
```

### Token flow

```mermaid
sequenceDiagram
    participant C as Client
    participant S as go-auth
    participant P as Identity Provider
    participant R as Resource Server

    C->>S: GET /auth/authorize?code_challenge=...
    S->>P: Redirect to provider login
    P->>S: Callback with auth code
    S->>C: Authorization code
    C->>S: POST /auth/code (code + code_verifier)
    S->>S: Verify PKCE, exchange with provider
    S->>S: Upsert user + session in PostgreSQL
    S->>C: Signed JWT (access_token)
    C->>R: API request (Bearer token)
    R->>R: Validate JWT locally (RS256 + JWKS)
    R->>C: Response
```

## Development

Contributions are welcome.

### Makefile targets

| Target | Description |
|---|---|
| `make` | Build the WASM frontend and npm bundles |
| `make cmd` | Build the `authserver` binary |
| `make wasm` | Build the WebAssembly frontend only |
| `make npm` | Bundle Carbon web components via esbuild |
| `make license` | Add Apache 2.0 license headers to all `.go` files |
| `make tidy` | Run `go mod tidy` |
| `make clean` | Remove all build artefacts and tidy dependencies |

### Tests

```bash
go test ./...
```

Tests that require PostgreSQL use [testcontainers-go](https://github.com/testcontainers/testcontainers-go) and spin up a real database — Docker must be running.

## License

Copyright 2026 David Thorpe. Licensed under the [Apache License, Version 2.0](LICENSE).
