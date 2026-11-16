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
