# LDAP Manager

Manages an LDAP directory: its users, groups and their members, and any entry, by its distinguished name (DN).

- **Directories:** OpenLDAP, 389 Directory Server, and Active Directory, or Samba, which is like it.
- **Base DN:** every DN is under the manager's base DN. A DN can be relative to it, such as `ou=users`.
- **Attributes:** an entry's attributes are `attrs`, by name, with a list of values each. A value which isn't UTF-8, such as a certificate, is `{"base64": "..."}`.
- **Pages:** lists have `offset` and `limit`, which is 1000 at most, and `count`, which is all which match. `filter` is an LDAP filter, such as `(cn=a*)`, and `attr` the attributes to return.
- **Changes:** with a broadcaster, the manager publishes the changes it makes, and its connection coming up or going down, with schema `ldap`.

## Directory Schema

The object classes and attribute types the directory has, from its subschema entry, by name.

### GET /class

Lists the object classes.

- **Filters:** `filter` is a name or OID, `kind` is `ABSTRACT`, `STRUCTURAL` or `AUXILIARY`, and `superior`, `must` and `may` are attributes they all have.
- A class without a kind is `STRUCTURAL`.

### GET /attr

Lists the attribute types.

- **Filters:** `filter` is a name or OID, `usage`, `superior`, and the flags `obsolete`, `singleValue`, `collective` and `noUserModification`.
- An attribute type without a usage is `userApplications`.

## Users

Entries directly under the users' DN, by name: `uid`, or `cn` in Active Directory.

- **Object classes:** those the manager has, or those the directory has: one structural, such as `inetOrgPerson` or Active Directory's `user`, and `posixAccount`, when it has it.
- **IDs:** a `posixAccount` without a `uidNumber` has the next one.
- **Renaming:** changing the name in an update renames the user.

### GET /user

Lists the users.

- **`group`:** lists only the group's members.

### GET /user/{name}

Returns a user.

### PUT /user/{name}

Creates a user, with the attributes, which can be none.

- **Password:** `userPassword`, or `unicodePwd`, is set. An Active Directory user is enabled once it's set, and stays disabled without one.
- **`allocate_gid`:** sets the `gidNumber` to the `uidNumber`.

### PATCH /user/{name}

Updates a user. Attributes with values replace those it has, and attributes without values are deleted.

### DELETE /user/{name}

Deletes a user, and returns it, as it was.

## Groups

Entries directly under the groups' DN, by `cn`.

- **Object classes:** those the manager has, or those the directory has, such as `groupOfNames`, Active Directory's `group`, and `posixGroup`.
- **IDs:** a `posixGroup` without a `gidNumber` has the next one.
- **Members:** in `member` or `uniqueMember`, by DN, and in `memberUid`, by name. A group which needs a member has itself, when it has no others.

### GET /group

Lists the groups.

- **`user`:** lists only the groups the user is a member of.

### GET /group/{name}

Returns a group.

### PUT /group/{name}

Creates a group, with the attributes, which can be none.

### PATCH /group/{name}

Updates a group, as a user is updated. Changing its `cn` renames it.

### DELETE /group/{name}

Deletes a group, and returns it, as it was.

### POST /group/{name}/user

Adds the users, by name, a JSON list, to a group. Members already there are left as they are.

### DELETE /group/{name}/user

Removes the users, by name, a JSON list, from a group. Users who aren't members are left as they are.

## Objects

Any entry, by DN, which is escaped as a path segment, such as `ou=users,dc=example,dc=com` as `ou=users%2Cdc=example%2Cdc=com`, or as it is.

### GET /object

Lists the entries under the base DN.

- **`prefix`:** lists the subtree of a DN, with the entry itself.

### GET /object/{dn}

Returns an entry.

### PUT /object/{dn}

Creates an entry, with the attributes, which need an `objectClass`. Its parent must exist.

### PATCH /object/{dn}

Updates an entry. Attributes with values replace those it has, and attributes without values are deleted.

- **Renaming:** changing a value of its RDN renames it, under the same parent. When the changes after a rename fail, the rename is undone.

### DELETE /object/{dn}

Deletes an entry, which has no children, and returns it, as it was.

### POST /object/{dn}/bind

Checks an entry's password, which is the body, as plain text, and returns the entry, or 401.

- It binds on a connection of its own, so the manager stays bound as its own user.

### POST /object/{dn}/password

Changes an entry's password, and returns it, with the password, when it's generated.

- **`old`:** with it, the entry changes its own password, so it's checked. Without it, the manager resets it.
- **`new`:** without it, a password is generated.
- **Active Directory:** needs ldaps.
