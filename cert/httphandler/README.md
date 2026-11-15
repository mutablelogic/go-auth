# Certificate Manager

Manages X.509 certificate authorities and leaf certificates, from a root certificate.

- **Chain of trust:** root → intermediate certificate authority (CA) → leaf certificate.
- **Key:** a certificate is identified by its name and serial number. Its latest version is the one created last.
- **Root:** imported once, when the server starts. It can't be renewed, replaced or updated through the API, and only signs CAs.
- **Private keys:** encrypted at rest with the server's storage passphrases. A leaf certificate's key is returned by its own operation, which needs `cert:key`. A CA's never is.
- **Expiry:** the default is five years for a CA and 90 days for a leaf certificate. It's capped at the signer's expiry.

## Certificate Authorities

Intermediate certificate authorities, signed by the root. They have no SAN entries.

Renewing a CA creates a new version, with the next serial, signed by the root. The current version stays enabled, so its leaf certificates still work until it's disabled or expires. Renewing those leaf certificates signs them with the new version.

### POST /ca

Creates a certificate authority, signed by the root.

- The name is its common name, and must not exist.
- Its subject comes from the root's, with the fields in the request replacing them. An empty field removes it.
- The root must be enabled, and a storage passphrase configured.

### POST /ca/{name}/renew

Renews the latest version of a certificate authority.

- Its SAN entries and tags are kept.
- Its subject and expiry can be changed in the request. Fields which aren't set are kept.
- It must be enabled.

### POST /ca/{name}/{serial}/renew

Renews a version of a certificate authority, as renewing by name does.

## Certificates

Leaf certificates, signed by a certificate authority. Listing and updating include the CAs.

- **SAN entries:** DNS names, wildcards, IP addresses and CIDR ranges.
- **Metadata:** the enabled state and tags can be changed. Disabling a certificate disables those it signed. Tags are inherited from the signers, as effective tags.
- **Renewal:** creates a new version, with the next serial, and disables the current one. It's signed by the latest version of the certificate authority which signed it.

### GET /cert

Lists certificates, other than the root, without their private keys.

- **Filters:** `is_ca`, `enabled`, `valid` (within its validity period), `tags` (all of them) and `subject`.
- **Pages:** `offset` and `limit`.

### GET /cert/{name}

Returns the latest version of a certificate.

- **`chain`:** includes its issuers, up to the root.
- A disabled certificate is a conflict.

### GET /cert/{name}/key

Returns the latest version of a leaf certificate, with its private key, decrypted.

- It's a separate operation, which needs `cert:key`, so reading certificates doesn't give their keys.
- **`chain`:** includes its issuers, up to the root.
- A certificate authority's key is never returned, and a disabled certificate is a conflict.

### POST /cert/{name}

Creates a leaf certificate, signed by the latest version of the certificate authority with the name.

- The request has the certificate's name, which must not exist, and its SAN entries, expiry, subject and tags.
- Its subject comes from the CA's, with the fields in the request replacing them.
- The CA must be enabled, and not the root.

### PATCH /cert/{name}

Updates the enabled state and tags of the latest version of a certificate.

- Its SAN entries, subject and expiry can only be changed by renewing it.
- The root can't be updated.

### GET /cert/{name}/{serial}

Returns a version of a certificate, as getting it by name does.

### GET /cert/{name}/{serial}/key

Returns a version of a leaf certificate, with its private key, as getting it by name does.

### POST /cert/{name}/{serial}

Creates a leaf certificate, signed by a version of a certificate authority, as creating it by name does.

### PATCH /cert/{name}/{serial}

Updates the enabled state and tags of a version of a certificate.

### POST /cert/{name}/renew

Renews the latest version of a leaf certificate.

- Its SAN entries and tags are kept.
- Its subject and expiry can be changed in the request. Fields which aren't set are kept.
- It and its certificate authority must be enabled.

### POST /cert/{name}/{serial}/renew

Renews a version of a leaf certificate, as renewing by name does.
