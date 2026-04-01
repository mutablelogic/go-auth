# LDAP Manager

This service provides operational handlers for managing users, groups, and
generic LDAP objects through a directory server. All entries are identified
by their **common name** (`cn`) or **distinguished name** (`dn`). User and
group operations target well-known organisational units configured in the
LDAP manager; generic object operations work against arbitrary DNs within
the directory tree.

Pagination is controlled by `limit` and `offset` query parameters. An
optional `filter` parameter restricts results to entries whose name
contains the given substring.

## Object Schema

The LDAP subschema entry describes the object classes and attribute types
supported by the directory. These endpoints expose that schema information
so that clients can discover available classes and attributes without
querying the directory directly.

### GET /{prefix}/class

List object classes.

Returns a filtered, paginated list of LDAP object classes from the
subschema entry. Results can be filtered by name substring, kind
(abstract, structural, auxiliary), and boolean flags such as `obsolete`,
`must`, `may`, and `superior`.

### GET /{prefix}/attr

List attribute types.

Returns a filtered, paginated list of LDAP attribute types from the
subschema entry. Results can be filtered by name substring, usage
(userApplications, directoryOperation, distributedOperation, dSAOperation),
and boolean flags such as `obsolete`, `singleValue`, `collective`,
`noUserModification`, and `superior`.

## Users

Users are entries stored under the configured user organisational unit.
Each user is identified by a common name (`cn`). User entries can be
listed, retrieved, created, updated, and deleted. When creating a user,
an optional `allocate_gid` query parameter instructs the server to
assign the next available GID number. If the naming attribute changes
during an update, the entry is renamed first.

### GET /{prefix}/user

List users.

Returns a paginated list of LDAP users. Results can be filtered by name
substring. Pagination is controlled by `limit` and `offset`.

### GET /{prefix}/user/{cn}

Get user.

Returns a single LDAP user by common name.

### PUT /{prefix}/user/{cn}

Create user.

Creates a new LDAP user with the given common name. The request body
supplies optional attributes for the new entry. If a user with the
same name already exists the request is rejected.

### PATCH /{prefix}/user/{cn}

Update user.

Updates LDAP user attributes for the specified common name. If the user
naming attribute changes, the entry is renamed first. The request body
contains the attribute modifications.

### DELETE /{prefix}/user/{cn}

Delete user.

Deletes the LDAP user with the given common name and returns the deleted
entry.

## Groups

Groups are entries stored under the configured group organisational unit.
Each group is identified by a common name (`cn`). Groups can be listed,
retrieved, created, updated, and deleted. Group membership is managed
through a separate endpoint that accepts a list of user common names to
add or remove.

### GET /{prefix}/group

List groups.

Returns a paginated list of LDAP groups. Results can be filtered by name
substring. Pagination is controlled by `limit` and `offset`.

### GET /{prefix}/group/{cn}

Get group.

Returns a single LDAP group by common name.

### PUT /{prefix}/group/{cn}

Create group.

Creates a new LDAP group with the given common name. The request body
supplies optional attributes for the new entry. If a group with the
same name already exists the request is rejected.

### PATCH /{prefix}/group/{cn}

Update group.

Updates LDAP group attributes for the specified common name. If the group
naming attribute changes, the entry is renamed first. The request body
contains the attribute modifications.

### DELETE /{prefix}/group/{cn}

Delete group.

Deletes the LDAP group with the given common name and returns the deleted
entry.

### POST /{prefix}/group/{cn}/user

Add users to group.

Adds the named users to the LDAP group. The request body is a JSON array
of user common names. Existing members are ignored.

### DELETE /{prefix}/group/{cn}/user

Remove users from group.

Removes the named users from the LDAP group. The request body is a JSON
array of user common names. Users not currently in the group are ignored.

## Object

Generic LDAP object operations work against arbitrary distinguished names
within the directory tree. These endpoints are useful for managing entries
that do not fit the user or group organisational units, or for
administrative tasks that require direct DN access.

### GET /{prefix}/object

List objects.

Returns a filtered, paginated list of LDAP objects. Results can be
filtered by name substring. Pagination is controlled by `limit` and
`offset`.

### GET /{prefix}/object/{dn}

Get object.

Returns a single LDAP object by distinguished name.

### PUT /{prefix}/object/{dn}

Create object.

Creates an LDAP object at the specified distinguished name. The request
body supplies the object classes and attributes.

### PATCH /{prefix}/object/{dn}

Update object.

Updates LDAP object attributes at the specified distinguished name.

### DELETE /{prefix}/object/{dn}

Delete object.

Deletes the LDAP object at the specified distinguished name and returns
the deleted entry.

### POST /{prefix}/object/{dn}/bind

Bind object.

Attempts to bind (authenticate) as the specified LDAP object using the
supplied password. The request body is the plaintext password. A
successful bind returns the object entry; invalid credentials return a
401 error.

### POST /{prefix}/object/{dn}/password

Change object password.

Changes the password for the specified LDAP object. The request body
contains the old password and optionally a new password. If the new
password is omitted, the server generates one and returns it in the
response.
