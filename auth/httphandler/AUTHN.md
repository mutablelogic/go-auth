# Authentication & Identity Provider Handlers

Registers the public auth, OIDC, and protected-resource endpoints exposed by the auth server.

## Auth

Auth is the server's local authentication layer. It starts browser sign-in, exchanges provider credentials for locally signed tokens, publishes discovery metadata, and returns the authenticated user's client-facing claims.

### `GET /config`

Returns a `PublicClientConfigurations` object keyed by provider name. Each value is a `PublicClientConfiguration` containing only client-safe fields such as `issuer` and `client_id`.

### `GET /auth/authorize`

Accepts the `AuthRequest` query shape. This is the provider-specific `AuthorizationRequest` plus an optional `provider` key, so the actual query parameters are `redirect_uri`, `state`, `scope`, `nonce`, `code_challenge`, `code_challenge_method`, `login_hint`, and optionally `provider`. On success the endpoint responds with `302 Found` and redirects the browser to the selected provider flow. If the request includes a valid `redirect_uri` and `state`, early authorization failures are also redirected back to the callback with OAuth-style `error` and `error_description` query parameters.

### `POST /auth/code`

Accepts either an `AuthorizationCodeExchangeRequest` or a `RefreshTokenGrantRequest`, in JSON or OAuth-style form encoding, and returns an `oauth2.Token` response. The `authorization_code` request uses the `schema.AuthorizationCodeRequest` fields: `provider`, `code`, `redirect_uri`, optional `code_verifier`, optional `nonce`, and optional `meta`. The `refresh_token` request uses `grant_type=refresh_token` with a `refresh_token` field. Both success paths return a bearer `access_token`, `refresh_token`, `token_type`, `expiry`, and `expires_in`.

### `POST /auth/revoke`

Accepts a `RevokeRequest` in either JSON or form encoding, with a single `token` field, and returns `204 No Content` on success.

### `GET /auth/userinfo`

Returns a `schema.UserInfo` response for the authenticated local bearer token. The payload contains the client-facing identity claims `sub`, `email`, `name`, `groups`, and `scopes`.

### `GET /.well-known/openid-configuration`

Returns an `oidc.OIDCConfiguration` discovery document for locally issued tokens.

### `GET /.well-known/oauth-protected-resource`

Returns an `oidc.ProtectedResourceMetadata` document describing this server as a bearer-token resource. The payload includes the canonical `resource` identifier, the `authorization_servers` that issue accepted tokens, the supported `bearer_methods_supported`, and optional discovery hints such as `scopes_supported`, `resource_documentation`, and `resource_name`.

### `GET /.well-known/jwks.json`

Returns an `oidc.JSONWebKeySet` used to verify locally issued JWTs. The top-level `keys` array contains one or more `oidc.JSONWebKey` objects with fields such as `kid`, `kty`, `alg`, `use`, `n`, and `e`.

## Identity Provider

An identity provider is an upstream login source such as the built-in local flow or an external provider like Google. The auth server uses provider configuration to redirect the user, verify the returned identity, and mint a local session token.
