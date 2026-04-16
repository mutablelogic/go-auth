# certmanager

`cert/manager` is the certificate lifecycle package used by `go-auth` for managing an internal PKI in PostgreSQL. It stores a single root certificate, issues intermediate certificate authorities and leaf certificates beneath that root, encrypts all stored private key material with application-supplied passphrases, and exposes a small manager API that higher layers can wrap with HTTP and CLI interfaces.

The intended chain is:

```text
root -> intermediate CA -> leaf certificate
```

This package is designed that it can be embedded directly in a Go service, or in an existing server-side or client-side CLI  or run as a network service.

> **Not production ready.** This project is under active development and has known gaps (see below). Do not use it to protect production systems.

## Motivation

`cert/manager` exists to provide a compact certificate authority subsystem that fits the rest of the `go-auth` model:

- **PostgreSQL-backed state.** Certificates, subjects, tags, and version history are stored in PostgreSQL rather than scattered across files on disk.
- **Encrypted private keys.** Private key bytes are encrypted before being persisted, using versioned storage passphrases supplied by the host process.
- **Versioned certificate lifecycle.** Renewals create a new serial for the same logical certificate name and disable the previous version.
- **Embeddable manager API.** The core package focuses on domain logic. HTTP routes, JSON transport, and CLI commands wrap the manager rather than duplicating certificate logic.

## Capabilities

The manager supports these operations today:

- Bootstrap the database schema on first use.
- Import exactly one root certificate from a PEM bundle containing the certificate and matching RSA private key.
- Create intermediate certificate authorities signed by the stored root.
- Create leaf certificates signed by an explicit non-root CA.
- Renew leaf certificates and intermediate CAs by issuing a new serial and disabling the previous version.
- Update certificate metadata after issuance, currently enabled state and tags.
- List certificates with filters over type, enabled state, tags, validity, and subject.
- Retrieve certificate chains without private material.
- Retrieve decrypted private key material for exact non-CA certificate versions.

Not yet implemented:

- Storage passphrase rotation for previously encrypted private keys.
- Automatic certificate rotation before expiry.
- Scopes and permissions for multi-user use cases.
- Frontend (web) interface for managing certificates.
- Deletion of certificates and certificate authorities.
- Rotation of the root certificate.
- Importing certificates not signed or issued by the stored root or intermediate CAs.
- ACME protocol support (ie, Let's Encrypt).

Notable lifecycle rules:

- The root certificate is unique and cannot be renewed through the same renewal flow as non-root certificates.
- Leaf certificates must be signed by an intermediate CA, never directly by the root.
- CA creation does not accept SAN entries; leaf certificate creation does.
- Renewal preserves the existing SAN and tags, but can overlay subject fields and expiry.
- Disabled certificates and CAs cannot be renewed.

## Quick Start

### Prerequisites

- A built `certmanager` binary from `./cmd/certmanager`
- A PostgreSQL database reachable via `PG_URL` or `--pg.url`
- At least one storage passphrase supplied with `CERTMANAGER_PASSPHRASES` or `--storage-passphrase`
- A root PEM bundle if you are bootstrapping a new PKI

### Build the CLI

```bash
make cmd/certmanager
```

The binary is written to `build/certmanager`.

### Bootstrap and run the server

Generate a traditional RSA private key and self-signed root certificate with OpenSSL:

```bash
openssl genrsa -traditional -aes256 -out root.key.pem 4096

export ROOTKEY_PASSPHRASE='<passphrase>'
openssl req \
  -x509 \
  -new \
  -key root.key.pem \
  -passin env:ROOTKEY_PASSPHRASE \
  -sha256 \
  -days 3650 \
  -out root.crt.pem \
  -subj "/CN=Example Root CA/O=Example Org"

cat root.crt.pem root.key.pem > root.bundle.pem

certmanager bootstrap \
  --pg.url="postgres://user:password@localhost/authdb" \
  --certificate-pem root.bundle.pem
  --certificate-passphrase="$ROOTKEY_PASSPHRASE"
```

If the PEM bundle contains an unencrypted private key, `CERTMANAGER_CERTIFICATE_PASSPHRASE` or `--certificate-passphrase` can be omitted.

### Start the server

```bash
certmanager --http.addr='localhost:8084' run
```

For multi-tenancy use cases, you can use `--pg.schema` to isolate in a separate PostgreSQL schemas within the
same database (or use different databases with different `PG_URL` values). The manager will create the necessary tables in the specified schema on first use.

## CLI usage

The `certmanager` binary doubles as a CLI client. Set `CERTMANAGER_ADDR` to the host and port of the running server so you do not need to repeat `--http.addr` on every command:

```bash
export CERTMANAGER_ADDR=localhost:8084
```

Create an intermediate CA, issue a leaf certificate from it, inspect the PEM chain, and renew the leaf certificate:

```bash
# Create an intermediate CA named "issuer-ca" with a 1 year expiry and "platform" tag
certmanager ca-create issuer-ca \
  --expiry=8760h \
  --organization='Example Org' \
  --tag=platform

# Create a leaf certificate named "api.example.test" signed by "issuer-ca" with a 90 day expiry, two SAN entries, and an "edge" tag
certmanager cert-create api.example.test issuer-ca \
  --expiry=2160h \
  --san=api.example.test \
  --san=127.0.0.1 \
  --tag=edge

# Get the certificate chain for "api.example.test" in PEM format
certmanager cert api.example.test \
  --chain

# Get the private key for "api.example.test"
certmanager cert api.example.test \
  --private

# Renew "api.example.test" with a new 90 day expiry and postal code subject field, preserving SAN and tags
certmanager cert-renew api.example.test \
  --expiry=2160h \
  --postal-code=10967

# Update "api.example.test" to disable it and replace tags with "dont-use"
certmanager cert-update api.example.test \
  --disable \
  --tag=dont-use
```

The CLI can return the private key for leaf certificates with `cert --private`, but CA private keys are not exposed.
Renewal issues a new serial, preserves the existing SAN and tags, and disables the previous version.

## Architecture

### Relevant paths

| Path | Description |
|---|---|
| `cmd/certmanager/` | Binary entrypoint that assembles server commands, OpenAPI commands, and the certificate manager CLI |
| `cert/manager/` | Core certificate lifecycle logic: schema bootstrap, root import, issuance, renewal, metadata updates, and private key access |
| `pkg/cert/` | Certificate and key generation helpers used when creating roots, intermediate CAs, and leaf certificates |
| `crypto/` | Cryptographic helpers used for storage passphrases, key wrapping, and private key protection |
| `cert/schema/` | Shared request, response, and metadata models used by the manager, handlers, client, and CLI |
| `cert/httphandler/` | HTTP routes that expose the manager over the network |
| `cert/httpclient/` | Typed client for calling those HTTP routes |
| `pkg/cert/cmd/` | Client-side CLI commands and PEM-oriented output formatting |

### Component diagram

```mermaid
flowchart TD
  CLI["<b>CLI Binary</b> (cmd/certmanager)"]
  Cmd["<b>CLI Commands</b> (pkg/cert/cmd)"]
  Client["<b>HTTP Client</b> (cert/httpclient)"]
  Handlers["<b>HTTP Handlers</b> (cert/httphandler)"]
  Manager["<b>Manager</b> (cert/manager)"]
  Cert["<b>Certificate Helpers</b> (pkg/cert)"]
  Crypto["<b>Crypto</b> (crypto)"]
  Schema["<b>Schema</b> (cert/schema)"]
  PG[("<b>PostgreSQL</b>")]

  CLI -->|run / bootstrap| Manager
  CLI -->|run| Handlers
  CLI -->|cert, certs, ca-*| Cmd
  Cmd --> Client
  Client --> Handlers
  Cmd --> Schema
  Client --> Schema
  Handlers --> Schema
  Handlers --> Manager
  Manager --> Cert
  Manager --> Crypto
  Manager --> Schema
  Manager --> PG
```

### Embedded usage

Create a manager, bootstrap the schema, and optionally import the root certificate on first start:

```go
import (
  "context"
  "os"
  "time"

  manager "github.com/mutablelogic/go-auth/cert/manager"
  schema "github.com/mutablelogic/go-auth/cert/schema"
  types "github.com/mutablelogic/go-server/pkg/types"
)

func main() {
  rootPEM, err := os.ReadFile("root.bundle.pem")
  if err != nil {
    return err
  }

  // Only include manager.WithRoot(...) during initial bootstrap.
  m, err := manager.New(
    context.Background(),
    pool,
    manager.WithSchema("certmanager"),
    manager.WithPassphrase(1, os.Getenv("CERT_STORAGE_PASSPHRASE")),
    manager.WithRoot(string(rootPEM)),
  )
  if err != nil {
    return err
  }
  defer m.Close()  
}
```

If the root has already been imported, construct the manager without `manager.WithRoot(...)` and
provide only the storage passphrase(s) needed to decrypt stored private keys.
Create an intermediate CA and then a leaf certificate:

```go
ca, err := m.CreateCA(context.Background(), schema.CreateCertRequest{
  Name:   "issuer-ca",
  Expiry: 365 * 24 * time.Hour,
  Tags:   []string{"platform"},
})
if err != nil {
  return err
}

leaf, err := m.CreateCert(context.Background(), schema.CreateCertRequest{
  Name:   "api.example.test",
  Expiry: 90 * 24 * time.Hour,
  SAN:    []string{"api.example.test", "127.0.0.1"},
  Tags:   []string{"edge"},
}, ca.CertKey)
if err != nil {
  return err
}
```

Renew the leaf certificate while overriding part of the subject:

```go
renewed, err := m.RenewCert(context.Background(), leaf.CertKey, schema.RenewCertRequest{
  Expiry: 90 * 24 * time.Hour,
  Subject: &schema.SubjectMeta{
    PostalCode: types.Ptr("10967"),
  },
})
if err != nil {
  return err
}
```

## Appendix: Storage Passphrases

Storage passphrases protect private keys at rest in PostgreSQL. They are distinct from any passphrase used to encrypt a PEM file on disk before import.

- Passphrases are versioned by the `version` argument to `manager.WithPassphrase(version, value)`.
- The manager uses the configured passphrase version to encrypt newly stored private keys.
- Existing private keys can only be decrypted when the correct passphrase version is configured in memory.
- If no storage passphrase is configured, operations that need private key encryption or decryption fail.

Operationally, this means the host process must provide the passphrase set needed for both:

- decrypting any existing stored private keys it needs to use
- encrypting any new or renewed certificates it creates
