# Sign In

Signs people in with providers, such as Google, GitHub and LDAP, which say who they are: an identity, which is exchanged once they have. Its paths are under `auth/`, and need no authentication.

- **Redirect providers:** such as Google and GitHub, are signed in with at their own pages. `login` redirects to the provider, which redirects back to `callback`, with a code, which is exchanged, with PKCE.
- **Password providers:** such as LDAP, are signed in with a username and password, posted to `login`.
- **State:** the state and PKCE verifier of a sign-in are in a cookie, which is encrypted, for the provider's paths, for ten minutes, and cleared by the callback.
- **Sessions:** a session's token is returned once, and set as an `HttpOnly` cookie, for the API's paths, so a browser sends it. A request has it as a bearer token, or the cookie.
- **Returning:** with `return`, a path on the server, such as `/`, signing in redirects there (`303`), rather than returning the session, as a browser does.
- **Exchange:** an identity is exchanged for what the server makes of it, such as a session, with its token, which is returned once, or else the identity itself.

## Sign In

### GET /auth/provider

Lists the providers: their names, which are in their paths, labels, to show, and kinds, `redirect` or `password`.

### GET /auth/{provider}/login

Redirects to a redirect provider's sign-in page, with the state of the sign-in in a cookie. With `return`, the callback redirects to the path, once signed in.

### POST /auth/{provider}/login

Signs in with a password provider, with a `username` and `password`, as JSON or a form, and redirects to `return`, when it's set, or else returns what the identity is exchanged for, such as a session. A username which isn't found, and a password which isn't right, are the same `401`.

### GET /auth/{provider}/callback

Where a redirect provider returns, with a `code` and the `state`, or an `error`. The state must be the sign-in's, from its cookie, which is cleared. Returns what the identity is exchanged for.

### GET /auth/session

Returns the session of the request's token: who signed in, with which provider, their scopes, and when it expires.

### POST /auth/logout

Signs out: ends the session of the request's token, and clears its cookie.

## OAuth

With OAuth, the server is an OAuth authorization server for its API, as MCP clients expect: they discover it, register, and are authorized by whoever's signed in, for a session of their own.

- **Discovery:** the API's protected resource metadata (RFC 9728) names this server, whose metadata (RFC 8414) has its endpoints. A `401` says where the metadata is.
- **Clients:** are public, with PKCE (S256), and aren't kept: a client's ID is its registration, encrypted. They redirect to loopback URIs, on any port, or to ones the server allows.
- **Authorizing:** whoever's signed in authorizes a client, without being asked, or else signs in first, and returns. The code lasts a minute, and is exchanged once.
- **Tokens:** a code is exchanged for a session of its own, with the scopes asked for which the person has, which ends with theirs, and can be revoked. There are no refresh tokens.

### GET /.well-known/oauth-protected-resource

Returns the API's protected resource metadata: the resource, which is the API's URL, and its authorization server, which is this one. It's also at the path with the API's prefix after it, such as `/.well-known/oauth-protected-resource/api`.

### GET /.well-known/oauth-authorization-server

Returns the authorization server's metadata: its issuer, which is the server's URL, its endpoints, and what they support.

### POST /auth/register

Registers a client (RFC 7591), with its `redirect_uris`, and returns its `client_id`. A redirect URI is a loopback one, such as `http://127.0.0.1:8080/callback`, or one the server allows.

### GET /auth/authorize

Authorizes a client, with PKCE: redirects to its redirect URI, with a `code`, the `state` and the issuer, as `iss`, or an `error`. When no one's signed in, it redirects to sign in, which returns here. Without a valid client, or redirect URI, it's `400`.

### POST /auth/token

Exchanges a `code`, once, with its `client_id`, `redirect_uri` and `code_verifier`, as a form, for a session's token, as `access_token`, which is a bearer token.
