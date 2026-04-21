# Auth HTTP Handlers

Registers the public auth, OIDC, protected-resource, and authenticated management endpoints exposed by the auth server.

## Auth & Identity Provider Handlers

Public-facing authentication and discovery endpoints used by browsers, OAuth clients, and protected resources.

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

## Authorization Management Handlers

Authenticated management API used to inspect and modify users, groups, scopes, API keys, and change notifications inside the auth domain.

These endpoints sit behind the manager prefix configured by the server, so the OpenAPI descriptions use `{prefix}` as a placeholder for the mounted base path. When authentication is enabled, the bearer token scopes listed on each operation are enforced by the router configuration.

## User

User operations manage the local user records that are created from provider logins or added directly through the management API. They cover listing, CRUD operations on a single user, and batch changes to group membership.

### `GET /{prefix}/user`

Accepts the `UserListRequest` query shape and returns a `UserList` response. The request supports `offset`, `limit`, `email`, and repeated `status` query parameters. The response includes `count`, the applied `offset` and `limit`, and a `body` array of `User` records.

### `POST /{prefix}/user`

Accepts a `UserMeta` JSON body and returns the created `User` record.

### `GET /{prefix}/user/{user}`

Returns a single `User` record for the `{user}` UUID path parameter.

### `PATCH /{prefix}/user/{user}`

Accepts a `UserMeta` JSON body and returns the updated `User` record for the `{user}` UUID path parameter.

### `DELETE /{prefix}/user/{user}`

Deletes the specified user identified by the `{user}` UUID path parameter. On success the endpoint returns `204 No Content`.

### `POST /{prefix}/user/{user}/group`

Accepts a `UserGroupList` JSON body, which is an array of group IDs, and returns the updated `User` record after those memberships are added to the `{user}` UUID path parameter.

### `DELETE /{prefix}/user/{user}/group`

Accepts a `UserGroupList` JSON body, which is an array of group IDs, and returns the updated `User` record after those memberships are removed from the `{user}` UUID path parameter.

## Group

Group operations manage local authorization groups. Groups are used to organise users and attach scopes that later appear in issued tokens.

### `GET /{prefix}/group`

Accepts the `GroupListRequest` query shape and returns a `GroupList` response. The request supports `offset` and `limit`. The response includes `count`, the applied `offset` and `limit`, and a `body` array of `Group` records.

### `POST /{prefix}/group`

Accepts a `GroupInsert` JSON body and returns the created `Group` record. The `id` field in the request body is the stable group key.

### `GET /{prefix}/group/{group}`

Returns the `Group` record for the `{group}` path parameter.

### `PATCH /{prefix}/group/{group}`

Accepts a `GroupMeta` JSON body and returns the updated `Group` record for the `{group}` path parameter.

### `DELETE /{prefix}/group/{group}`

Deletes the named group identified by the `{group}` path parameter. On success the endpoint returns `204 No Content`.

## API Key

API key operations manage bearer-like opaque credentials owned by the authenticated local user. Key creation returns the plaintext token exactly once together with the stored metadata; later lookups and management operations work with the stored key record rather than reissuing the token value.

### `GET /{prefix}/key`

Returns a `KeyList` for the authenticated user. Query parameters support pagination and expiry filtering. The `user` filter is not accepted on this authenticated endpoint because the handler always scopes the request to the current user.

### `POST /{prefix}/key`

Accepts a `KeyMeta` JSON body and returns the created `Key` record. The response includes the generated plaintext `token` only on creation, along with the stored key `id`, owning `user`, timestamps, effective expiry, and the owning user's current `status`.

### `GET /{prefix}/key/{key}`

Returns the `Key` record for the `{key}` path parameter, for the authenticated user.

### `PATCH /{prefix}/key/{key}`

Accepts a `KeyMeta` JSON body and returns the updated `Key` record for the `{key}` path parameter, scoped to the authenticated user.

### `DELETE /{prefix}/key/{key}`

Deletes the API key identified by the `{key}` path parameter for the authenticated user. On success the endpoint returns `204 No Content`.

## Scope

Scope operations expose the scopes known to the auth manager. Scopes are read-only through this handler and are mainly used by clients and admin tooling to discover assignable permissions.

### `GET /{prefix}/scope`

Accepts the `ScopeListRequest` query shape and returns a `ScopeList` response. The request supports `offset`, `limit`, and the optional `q` substring filter. The response includes `count`, the applied `offset` and `limit`, and a `body` array of scope strings.

## Changes

Change operations expose a live notification stream for auth-domain mutations. They are intended for admin clients and tools that need to react to database-backed updates without polling.

### `GET /{prefix}/changes`

Produces a `text/event-stream` response and emits `ChangeNotification` payloads. Each event contains the changed `schema`, `table`, and `action` values reported by the manager notification stream.
