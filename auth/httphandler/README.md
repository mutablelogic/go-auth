# Auth HTTP Handlers

This package registers the authentication and OpenID Connect HTTP endpoints exposed by the auth server.

The handlers are wired by `RegisterAuthHandlers` and currently register these routes:

| Method | Path | Auth required | Purpose |
| --- | --- | --- | --- |
| `GET` | `.well-known/openid-configuration` | No | Return this server's OIDC discovery document |
| `GET` | `.well-known/oauth-protected-resource` | No | Return OAuth protected-resource metadata |
| `GET` | `.well-known/jwks.json` | No | Return the public signing keys used for local JWTs |
| `GET` | `auth/authorize` | No | Start a local browser authorization flow, or redirect to an explicit upstream provider |
| `POST` | `auth/code` | No | Exchange an authorization code or refresh token for local bearer tokens |
| `POST` | `auth/revoke` | No | Revoke a previously issued local session token |
| `GET` | `auth/userinfo` | Yes | Return the authenticated user's local claims |

## Common behavior

- All routes return `405 Method Not Allowed` for unsupported HTTP methods.
- JSON request bodies must use `Content-Type: application/json`.
- `POST /auth/code` and `POST /auth/revoke` accept form-encoded OAuth requests.
- `POST /auth/revoke` also accepts the local token in the JSON body, not in the `Authorization` header.
- `GET /auth/userinfo` is the only route in this package that is always wrapped with bearer-token middleware.
- Local tokens are signed by this server and include embedded `user` and `session` claims.

## Endpoint details

### `GET /auth/authorize`

Starts a browser authorization flow.

- Without `provider`, this endpoint issues a local testing authorization code and redirects straight back to the supplied callback.
- With `provider`, it redirects the browser to the configured upstream provider.

Query parameters:

- `client_id`: required. For local testing it is accepted as-is and echoed through the local auth-code flow.
- `redirect_uri`: required callback URI.
- `response_type`: optional, defaults to `code`. Only `code` is accepted.
- `state`: required and forwarded to the upstream provider.
- `provider`: optional. When omitted, the local testing flow is used. When set, it must name a configured upstream provider.
- `scope`: optional space-delimited scopes. Defaults to `openid email profile`.
- `nonce`: optional and forwarded to the upstream provider.
- `code_challenge`: optional PKCE challenge.
- `code_challenge_method`: optional PKCE method.
- `login_hint`: optional local testing email address used by the local flow. Defaults to `local@example.com`.

Success response: `302 Found`

- Redirects to the local callback with a short-lived local authorization code, or to the configured upstream provider authorization endpoint.

Typical error cases:

- `400 Bad Request` when required query parameters are missing.
- `400 Bad Request` when `response_type` is not `code`.
- `400 Bad Request` when the provider cannot be resolved from configuration.

### `POST /auth/code`

Exchanges an authorization code and returns local auth tokens.

- For local testing, this endpoint accepts a standard form-encoded OAuth token request and returns a local bearer token.
- For upstream providers, it accepts either the same form contract or the existing JSON request body.
- Refresh is also handled here with `grant_type=refresh_token`.

Request body:

```json
{
  "provider": "google",
  "code": "<authorization-code>",
  "redirect_url": "http://127.0.0.1:8085/callback",
  "code_verifier": "<optional-pkce-verifier>",
  "nonce": "<optional-expected-nonce>",
  "meta": {
    "invite": "optional"
  }
}
```

Notes:

- JSON mode: `provider`, `code`, and `redirect_url` are required.
- Local form mode: `grant_type=authorization_code`, `code`, `client_id`, and `redirect_uri` are required.
- If `nonce` is supplied in JSON mode, it must match the `nonce` claim in the upstream `id_token`.
- In local form mode, `code_verifier` must match the PKCE challenge when one was supplied during `/auth/authorize`.

Success response: `200 OK`

- Form mode returns an OAuth token response:

```json
{
  "access_token": "<local-jwt>",
  "refresh_token": "<local-jwt>",
  "token_type": "Bearer",
  "expires_in": 900
}
```

- JSON mode returns the legacy local token and `userinfo` response.

Typical error cases:

- `400 Bad Request` for missing fields, failed code exchange, missing upstream `id_token`, or nonce mismatch.

### `POST /auth/revoke`

Verifies a previously issued local token, extracts its session ID, and revokes that session.

Request body:

```json
{
  "token": "<local-jwt>"
}
```

Success response: `204 No Content`

Notes:

- The token is verified the same way as for refresh.
- Revocation marks the backing session as revoked.
- No response body is returned on success.

Typical error cases:

- `400 Bad Request` when `token` is missing, invalid, or missing the `sid` claim.
- `404 Not Found` when the referenced session no longer exists.

### `GET /auth/userinfo`

Returns the client-facing identity claims for the authenticated local bearer token.

Headers:

- `Authorization: Bearer <local-jwt>` is required.

Success response: `200 OK`

```json
{
  "sub": "<user-uuid>",
  "email": "user@example.com",
  "name": "Example User",
  "groups": ["group-a"],
  "scopes": ["scope-a"]
}
```

Typical error cases:

- `401 Unauthorized` when the bearer token is missing or invalid.
- `500 Internal Server Error` if authentication succeeded but the user object is missing from request context.

### `GET /.well-known/openid-configuration`

Returns the server's OpenID Connect discovery document for locally issued tokens.

Success response: `200 OK`

Includes values such as:

- `issuer`
- `authorization_endpoint`
- `token_endpoint`
- `jwks_uri`
- supported response, grant, scope, signing, and PKCE methods

Notes:

- The authorization endpoint points at this server's `/auth/authorize` route.
- The token endpoint points at this server's `/auth/code` route.

### `GET /.well-known/oauth-protected-resource`

Returns OAuth protected-resource metadata describing this server.

Success response: `200 OK`

Includes values such as:

- `resource`
- `authorization_servers`
- `bearer_methods_supported`
- `resource_name`

### `GET /.well-known/jwks.json`

Returns the JSON Web Key Set used to verify locally issued JWTs.

Success response: `200 OK`

Example shape:

```json
{
  "keys": [
    {
       "kid": "local-main",
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig"
    }
  ]
}
```

Typical error cases:

- `500 Internal Server Error` if the server cannot build its public key set.
