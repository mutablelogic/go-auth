# Auth & Identity Provider Handlers

Registers the public auth, OIDC, and protected-resource endpoints exposed by the auth server.

## Auth

Auth is the server's local authentication layer. It starts browser sign-in, exchanges provider credentials for locally signed tokens, publishes discovery metadata, and returns the authenticated user's client-facing claims.

### `GET /auth/config`

Returns the public upstream provider configuration keyed by provider name. Only client-safe fields such as issuer and public client ID are included.

### `GET /auth/authorize`

Starts a browser authorization flow. Without `provider`, it issues a local testing authorization code and redirects back to the callback. With `provider`, it redirects to the configured upstream provider.

### `POST /auth/code`

Handles both `authorization_code` and `refresh_token` grants. With `authorization_code`, it exchanges a provider-issued code for a new local bearer token pair. With `refresh_token`, it verifies an existing local refresh token and returns a fresh local bearer token pair. Supports OAuth-style form requests as well as the existing JSON request body.

### `POST /auth/revoke`

Revokes a previously issued local session token. Both the JSON and form-encoded request bodies accept the same `token` field.

### `GET /auth/userinfo`

Returns the client-facing identity claims for the authenticated local bearer token. Requires a valid bearer token issued by this server.

### `GET /.well-known/openid-configuration`

Returns this server's OpenID Connect discovery document for locally issued tokens.

### `GET /.well-known/oauth-protected-resource`

Returns OAuth protected-resource metadata describing this server as a bearer-token resource. The response includes the canonical `resource` identifier, the `authorization_servers` that issue accepted tokens, the supported `bearer_methods_supported`, and optional discovery hints such as `scopes_supported`, `resource_documentation`, and `resource_name`.

### `GET /.well-known/jwks.json`

Returns the public JSON Web Key Set used to verify locally issued JWTs. The top-level `keys` array contains one or more public signing keys. Each key includes the key identifier `kid`, key type `kty`, signing algorithm `alg`, intended use `use`, and the RSA public key material in `n` and `e`.

## Identity Provider

An identity provider is an upstream login source such as the built-in local flow or an external provider like Google. The auth server uses provider configuration to redirect the user, verify the returned identity, and mint a local session token.
