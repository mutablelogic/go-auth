# Auth Manager

This service provides operational handlers for managing local users, groups,
scopes, and real-time change notifications. Users are identified by a UUID;
groups and scopes are identified by short string identifiers.

Authentication can be enabled or disabled at registration time. When enabled,
all endpoints except the public configuration endpoint require a valid bearer
token.

## Configuration

The configuration endpoint exposes the upstream authentication provider
details that are safe for clients to consume without authentication. Clients
use this information to discover available login methods and token endpoints.

### GET /{prefix}/config

Get configuration.

Returns the public authentication configuration including the available
providers and their endpoints. This endpoint does not require authentication.

## User

Users represent local accounts managed by the auth system. Each user has a
UUID identifier, a canonical email address, a display name, and a lifecycle
status (new, active, inactive, suspended, deleted). Users can belong to one
or more groups which grant scopes.

### GET /{prefix}/user

List users.

Returns a filtered, paginated list of users. Results can be filtered by
canonical email address and one or more lifecycle statuses. Pagination is
controlled by `limit` and `offset`.

### POST /{prefix}/user

Create user.

Creates a new local user. The request body supplies the user name, email,
optional group memberships, and initial metadata.

### GET /{prefix}/user/{user}

Get user.

Returns a single user by UUID.

### PATCH /{prefix}/user/{user}

Update user.

Updates mutable fields on a user. The request body contains the fields to
change; omitted fields are left unchanged.

### DELETE /{prefix}/user/{user}

Delete user.

Deletes a user by UUID. Returns an empty response on success.

### POST /{prefix}/user/{user}/group

Add user groups.

Adds one or more groups to a user by UUID and returns the updated user.
The request body is a JSON array of group identifiers.

### DELETE /{prefix}/user/{user}/group

Remove user groups.

Removes one or more groups from a user by UUID and returns the updated user.
The request body is a JSON array of group identifiers.

## Group

Groups are named collections of scopes. Users are assigned to groups to
receive the scopes defined by those groups. Each group has a string
identifier, an optional description, an enabled flag, and a list of scopes.

### GET /{prefix}/group

List groups.

Returns a paginated list of groups. Pagination is controlled by `limit` and
`offset`.

### POST /{prefix}/group

Create group.

Creates a new group. The request body supplies the group identifier,
optional description, enabled state, scopes, and metadata.

### GET /{prefix}/group/{group}

Get group.

Returns a single group by identifier.

### PATCH /{prefix}/group/{group}

Update group.

Updates mutable fields on a group. The request body contains the fields to
change; omitted fields are left unchanged.

### DELETE /{prefix}/group/{group}

Delete group.

Deletes a group by identifier. Returns an empty response on success.

## Scope

Scopes are permission strings assigned to groups. The scope endpoint
provides a deduplicated, filterable view across all groups.

### GET /{prefix}/scope

List scopes.

Returns a paginated list of distinct scopes across all groups. Results can
be filtered by a substring match using the `q` parameter. Pagination is
controlled by `limit` and `offset`.

## Changes

The changes endpoint streams real-time table change notifications over
server-sent events. Clients must send an `Accept: text/event-stream` header.

### GET /{prefix}/changes

Stream changes.

Requires an Accept header of text/event-stream and streams change
notifications until the client disconnects. Each event contains the schema,
table, and action that triggered the notification.
