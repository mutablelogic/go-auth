# go-auth

Client and server authentication with local JWT sessions backed by PostgreSQL.

## Current model

- Authorization codes are exchanged for a locally signed JWT.
- The local JWT contains embedded `user` and `session` claims.
- Access tokens are short-lived and currently validated without a database lookup on normal protected requests.
- Session refresh and revoke operate on the backing PostgreSQL session row.

## Endpoints

- `POST /auth/code`: exchange an authorization code or refresh token for a local token.
- `POST /auth/revoke`: revoke a local session token.
- `GET /changes`: stream protected change notifications as server-sent events.
- `GET /user`: list users.
- `POST /user`: create a user.
- `GET /user/{user}`: fetch a user.
- `PATCH /user/{user}`: update a user.
- `DELETE /user/{user}`: delete a user.

## Token semantics

- Local access tokens are self-contained JWTs signed by the server.
- Protected routes verify the JWT signature, issuer, and embedded user/session claims.
- Revoking a session prevents refresh and future issuance, but does not immediately invalidate an already-issued access token.
- Changes to user status or expiry also take effect when a new token is issued or when the current token expires.
- The intended consistency model is short-lived access tokens, currently 15 minutes.

## OpenAPI

- Auth and user routes publish OpenAPI path items from the HTTP handler layer.
- UUID-backed identifiers use explicit OpenAPI schema overrides because `uuid.UUID`-backed Go types do not naturally render as `string` with `format: uuid`.
