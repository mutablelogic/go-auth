# Authorization Management Handlers

Registers the authenticated management API used to inspect and modify users, groups, scopes, and change notifications inside the auth domain.

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

## Scope

Scope operations expose the scopes known to the auth manager. Scopes are read-only through this handler and are mainly used by clients and admin tooling to discover assignable permissions.

### `GET /{prefix}/scope`

Accepts the `ScopeListRequest` query shape and returns a `ScopeList` response. The request supports `offset`, `limit`, and the optional `q` substring filter. The response includes `count`, the applied `offset` and `limit`, and a `body` array of scope strings.

## Changes

Change operations expose a live notification stream for auth-domain mutations. They are intended for admin clients and tools that need to react to database-backed updates without polling.

### `GET /{prefix}/changes`

Produces a `text/event-stream` response and emits `ChangeNotification` payloads. Each event contains the changed `schema`, `table`, and `action` values reported by the manager notification stream.
