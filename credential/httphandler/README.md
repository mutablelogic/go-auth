# Credential Handlers

## Credentials

Credentials store secret material, such as API keys or tokens, under a key, for other parts of the system to authenticate with third-party services. A credential's value is only returned with the passphrase it was encrypted with, so only for backends which encrypt with their own passphrases (file and pg). Other backends, such as AWS and Bitwarden Secrets Manager, never return values over HTTP.

### GET /credential

List the stored credentials in key order, without their values. Credentials from the environment aren't listed. Returns `count`, and the key of each credential with the time it was last changed, when the backend records it. Needs the `credential:read` scope.

### PUT /credential

Store a credential, replacing any credential with the same key. The request body is a JSON object with the `key`, an identifier of up to 64 letters, digits, `_` and `-`, starting with a letter, and the `credentials`, which can be any JSON value. Returns the key. Returns 400 if the key or credentials are invalid, 403 if the backend refuses the write, or 503 if the backend has no passphrase. Needs the `credential:write` scope.

### GET /credential/{key}

Get the key of a stored credential, and the time it was last changed, without its value. Use it to check that a credential exists. Returns 400 if the key is invalid, or 404 if there's no credential for the key. Needs the `credential:read` scope.

### POST /credential/{key}

Get a credential's value, with the passphrase it was encrypted with as the request body, as `text/plain`, which must match exactly, including any spaces or line endings. This is a `POST` rather than a `GET`, as the request has a body, and the response is sent with `Cache-Control: no-store`, so the value isn't cached. Returns the credential as JSON. Returns 400 if the key or request body is invalid, 403 if the passphrase isn't the credential's passphrase, or 404 if there's no credential for the key. Only for backends which encrypt with their own passphrases. Needs the `credential:decrypt` scope.

### DELETE /credential/{key}

Delete a stored credential. A credential from the environment can't be deleted. Returns 400 if the key is invalid, or 404 if there's no credential for the key. Needs the `credential:write` scope.

### POST /credential/{key}/rotate

Re-encrypt a credential with the latest passphrase version, without changing its value, after a new passphrase version is added. Returns 304 if the credential already uses the latest passphrase version, 400 if the key is invalid, 404 if there's no credential for the key, or 503 if no passphrase is configured. Only for backends which encrypt with their own passphrases. Needs the `credential:write` scope.
