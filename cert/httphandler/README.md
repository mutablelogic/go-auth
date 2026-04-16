# Certificate Manager

This service provides operational handlers for managing X.509 certificate authorities and
leaf certificates. A **certificate authority** (CA) is a trusted entity that issues and signs
certificates. A **leaf certificate** is an end-entity certificate signed by a CA, used to authenticate
a server, client, or service. Each certificate is identified by a **name** and a
**serial number**; together these form the certificate key.

Trust is established through a **chain of trust**: a leaf certificate is signed by an
intermediate or root CA, and each CA's certificate may in turn be signed by a higher-level CA.
A client verifies a leaf certificate by walking this chain back to a root CA it already trusts.
When requesting a certificate from this API, the `chain` query parameter can be used to include
the full issuer chain in the response.

The intended chain of trust is:

```text
root -> intermediate CA -> leaf certificate
```

The root certificate is imported once during bootstrap and cannot be renewed or replaced through
the API. All CAs created through the API are intermediate CAs signed by that root. Leaf
certificates must be signed by an intermediate CA, never directly by the root.

Certificates support **renewal**, which creates a new version (with a new serial number) and
disables the previous version. Renewal preserves the certificate name so that dependents
can continue to reference it without reconfiguration. SAN entries and tags are carried forward
from the previous version. Subject fields and expiry can be overridden in the renewal request;
omitted fields preserve the current values.

All private key material is encrypted at rest using versioned storage passphrases supplied by
the host process. At least one storage passphrase must be configured before any certificate
can be created. Private keys for CA certificates are never returned through the API; only
exact leaf certificate versions expose their decrypted private key via the `private` query
parameter.

## Certificate Authority

Intermediate certificate authorities are signed by the stored root certificate. They cannot
contain SAN entries and their expiry is capped to the remaining validity of the root. CAs
can be renewed to produce a new serial that replaces the previous version.

When renewing certificate authorities, if the requested expiry is zero or omitted, a
default is used (one year for CAs, 90 days for
leaf certificates). If the requested expiry exceeds the remaining validity of the signing
certificate, it is silently capped to that remaining validity.

### POST /{prefix}/ca

Create a new intermediate certificate authority signed by the stored root certificate.

The request name becomes the CA common name. Subject fields are inherited from the root
certificate and can be overridden in the request. SAN entries are not accepted for CA
certificates. If a certificate with the same name already exists the request is rejected.
The root certificate must be enabled and the server must have at least one storage passphrase
configured.

### POST /{prefix}/ca/{name}/renew

Renew the latest certificate authority version with the supplied name.

Looks up the latest CA version by name, issues a new serial signed by the root, and disables
the previous version in a single transaction. The new version inherits the existing SAN (none
for CAs) and tags. Subject fields and expiry can be overridden via the request body. The CA
must be enabled and must not be the root certificate.

### POST /{prefix}/ca/{name}/{serial}/renew

Renew a specific certificate authority version identified by name and serial number.

Behaves like renewal by name but targets an explicit version rather than the latest. This is
useful when multiple versions exist and a specific one should be the basis for renewal.

## Certificates

Leaf certificates are end-entity certificates signed by an intermediate CA. They support
SAN entries (DNS names, wildcards, IP addresses, CIDR ranges) and expose their decrypted
private key on request. Certificates can be listed, filtered, renewed, and have their
metadata (tags and enabled state) updated after issuance.

When renewing certificates, if the requested expiry is zero or omitted, a
default is used (one year for CAs, 90 days for
leaf certificates). If the requested expiry exceeds the remaining validity of the signing
certificate, it is silently capped to that remaining validity.

### GET /{prefix}/cert

List certificates.

Returns a paginated list of non-root certificates. Results can be filtered by CA status
(`is_ca`), enabled state (`enabled`), tags, current validity (`valid`), and subject fields.
Pagination is controlled by `limit` and `offset` query parameters.

### GET /{prefix}/cert/{name}

Get the latest certificate version by name.

Returns the latest certificate version for the supplied name. Use the `chain` query parameter
to include the full issuer chain (from the certificate up to the root) and `private` to
include the decrypted private key. Private keys are only returned for non-CA leaf certificates.
If the certificate is disabled the request is rejected.

### POST /{prefix}/cert/{name}

Create a leaf certificate signed by the named CA.

The path `{name}` identifies the signing CA by name; the latest enabled version of that CA is
used. The request body supplies the leaf certificate name, optional SAN entries (DNS names,
wildcard patterns, IP addresses, CIDR ranges), expiry, subject overrides, and tags. The
signing CA must be an intermediate (non-root) CA and must be enabled. SAN entries are validated
before issuance. A certificate with the requested name must not already exist.

### PATCH /{prefix}/cert/{name}

Update metadata on the latest certificate version.

Updates the enabled state and tags on the latest version of the named certificate. The root
certificate cannot be updated. Other fields (SAN, subject, expiry) are immutable after issuance
and can only be changed through renewal.

### GET /{prefix}/cert/{name}/{serial}

Get a specific certificate version.

Returns the requested certificate version by name and serial number. Supports the same `chain`
and `private` query parameters as the name-based endpoint. Disabled certificates are rejected.

### POST /{prefix}/cert/{name}/{serial}

Create a leaf certificate signed by a specific CA version.

The path identifies the signing CA by name and serial number. Behaves like creation by CA name
but uses an explicit CA version rather than the latest. This is useful when a specific CA
version must be the issuer.

### PATCH /{prefix}/cert/{name}/{serial}

Update metadata on a specific certificate version.

Updates enabled state and tags on the exact certificate version. The root certificate cannot
be updated.

### POST /{prefix}/cert/{name}/renew

Renew the latest certificate version with the supplied name.

Looks up the latest version by name, issues a new serial signed by the same CA that signed
the current version, and disables the previous version in a single transaction. The new
version inherits the existing SAN entries and tags. Subject fields and expiry can be overridden
via the request body. The certificate must be an enabled leaf certificate (not a CA), and its
signing CA must also be enabled.

### POST /{prefix}/cert/{name}/{serial}/renew

Renew a specific certificate version.

Behaves like renewal by name but targets an explicit version rather than the latest. The
specified version must be an enabled leaf certificate.
