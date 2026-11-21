# Credential Handlers

## Credentials

Credentials store secret material, such as API keys or tokens, under a key, for other parts of the system to authenticate with third-party services. A credential's value is only returned with the passphrase it was encrypted with, so only for backends which encrypt with their own passphrases (file and pg). Other backends, such as AWS and Bitwarden Secrets Manager, never return values over HTTP.

### GET /credential

List the stored credentials in key order, without their values. Credentials from the environment aren't listed. Returns `count`, and each credential's key and description, with the time it was last changed, when the backend records it. Needs the `credential:read` scope.

### PUT /credential

Store a credential, replacing any credential with the same key. The request body is a JSON object with the `key`, an identifier of up to 64 letters, digits, `_` and `-`, starting with a letter, and the `credentials`, which can be any JSON value, and, optionally, its `description`, such as what it's for, which is kept when it isn't set, and removed when it's empty. Returns the key, and the description, when it's set. Returns 400 if the key or credentials are invalid, 403 if the backend refuses the write, or 503 if the backend has no passphrase. Needs the `credential:write` scope.

### GET /credential/{key}

Get the key of a stored credential, its description, and the time it was last changed, without its value. Use it to check that a credential exists. Returns 400 if the key is invalid, or 404 if there's no credential for the key. Needs the `credential:read` scope.

### POST /credential/{key}

Get a credential's value, with the passphrase it was encrypted with as the request body, as `text/plain`, which must match exactly, including any spaces or line endings. This is a `POST` rather than a `GET`, as the request has a body, and the response is sent with `Cache-Control: no-store`, so the value isn't cached. Returns the credential as JSON. Returns 400 if the key or request body is invalid, 403 if the passphrase isn't the credential's passphrase, or 404 if there's no credential for the key. Only for backends which encrypt with their own passphrases. Needs the `credential:decrypt` scope.

### PATCH /credential/{key}

Change a stored credential's description, without its value. The request body is a JSON object with its `description`, which is removed when it's empty. Returns the key, and the description. Returns 400 if the key or request body is invalid, 403 if the backend refuses the write, or 404 if there's no credential for the key. Needs the `credential:write` scope.

### DELETE /credential/{key}

Delete a stored credential. A credential from the environment can't be deleted. Returns 400 if the key is invalid, or 404 if there's no credential for the key. Needs the `credential:write` scope.

### POST /credential/{key}/rotate

Re-encrypt a credential with the latest passphrase version, without changing its value, after a new passphrase version is added. Returns 304 if the credential already uses the latest passphrase version, 400 if the key is invalid, 404 if there's no credential for the key, or 503 if no passphrase is configured. Only for backends which encrypt with their own passphrases. Needs the `credential:write` scope.

### POST /credential/{key}/signin

Store a sign-in, as the credential, when the server registers an authorization server for the key's prefix, such as `GOOGLE_` for Google. A client, such as a command line tool, gets how to sign in from a server, signs in at the authorization server with PKCE, which redirects to a loopback address with a code, and sends the code here. The server exchanges it with the OAuth client which is the value of the client credential, such as `GOOGLE_CLIENT`, as its `client_id` and `client_secret`, or the file Google's console downloads, so the client's secret stays on the server. The grant, with its tokens, is stored without the secret. The request body is a JSON object with the `code`, its `code_verifier`, and the `redirect_uri`, which must be a loopback address. Returns the key, the server's issuer, and the scopes it granted, without the tokens. Returns 400 if the key, request body or redirect is invalid, the key isn't a sign-in's, or the server refuses the code, 403 if the backend refuses the write, or 503 if there's no client, the server refuses the client, or the server fails. Needs the `credential:write` scope.

### POST /credential/{key}/authorize

Sign in, in a browser, when the server registers a web client for the key's prefix's authorization server, such as `GOOGLE_WEB_CLIENT`, a web application's OAuth client, whose redirect URI is the server's callback. The request body is a JSON object with the `redirect_uri`, the server's `credential/callback`, as the browser reaches it, which must be registered with the web client, and the `scopes` to ask for, such as those of a sign-in error. Returns the `url` the person signs in at, with a state, and a PKCE challenge, whose verifier the server keeps, for ten minutes. Returns 400 if the key, request body or redirect is invalid, the key isn't a sign-in's, or its server has no web client, or 503 if there's no web client's credential, or it isn't a client. Needs the `credential:write` scope.

### GET /credential/callback

The redirect of a sign-in which was asked for with `POST /credential/{key}/authorize`: the server exchanges the `code`, of the `state`, which is done once, with the web client's secret, and the kept verifier, and stores the grant, without the secret, as the key's credential. Returns a page which says the person signed in, or why they aren't, which posts a `credential-signin` message, of the key, whether it's `ok`, and the `error`, to the window which opened it, of the same origin, and closes, once they are. Needs no scope, as its state, which is random, is the sign-in's.
