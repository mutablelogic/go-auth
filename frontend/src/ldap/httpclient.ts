// The client of the LDAP API, which go-auth's ldap/httphandler serves, at
// the client's prefix, such as /api, under ldap/

import { errorResponse, request, url, type Client } from '@mutablelogic/go-server/api';
import type {
    AttributeTypeList, AttributeTypeListRequest, Attrs, GroupListRequest, LdapObject, ObjectClassList,
    ObjectClassListRequest, ObjectList, ObjectListRequest, PasswordRequest, PasswordResponse, UserListRequest,
} from './schema.ts';

///////////////////////////////////////////////////////////////////////////////
// SCHEMA

// listObjectClasses returns a page of the directory's object classes
export async function listObjectClasses(client: Client, req: ObjectClassListRequest = {}, signal?: AbortSignal): Promise<ObjectClassList> {
    return request<ObjectClassList>(client, 'GET', withQuery('ldap/class', req), { signal });
}

// listAttributeTypes returns a page of the directory's attribute types
export async function listAttributeTypes(client: Client, req: AttributeTypeListRequest = {}, signal?: AbortSignal): Promise<AttributeTypeList> {
    return request<AttributeTypeList>(client, 'GET', withQuery('ldap/attr', req), { signal });
}

///////////////////////////////////////////////////////////////////////////////
// USERS

// listUsers returns a page of the users, or a group's members
export async function listUsers(client: Client, req: UserListRequest = {}, signal?: AbortSignal): Promise<ObjectList> {
    return request<ObjectList>(client, 'GET', withQuery('ldap/user', req), { signal });
}

// getUser returns the user with the name
export async function getUser(client: Client, name: string): Promise<LdapObject> {
    return request<LdapObject>(client, 'GET', path('ldap/user', name));
}

// createUser creates a user with the name, and the attributes. With
// allocateGID, its gidNumber is its uidNumber.
export async function createUser(client: Client, name: string, attrs: Attrs = {}, allocateGID = false): Promise<LdapObject> {
    return request<LdapObject>(client, 'PUT', path('ldap/user', name), { body: { attrs }, query: allocateGID ? { allocate_gid: true } : undefined });
}

// updateUser replaces the user's attributes with values, and deletes those
// with none. Changing its name renames it.
export async function updateUser(client: Client, name: string, attrs: Attrs): Promise<LdapObject> {
    return request<LdapObject>(client, 'PATCH', path('ldap/user', name), { body: { attrs } });
}

// deleteUser deletes the user, and returns it, as it was
export async function deleteUser(client: Client, name: string): Promise<LdapObject> {
    return request<LdapObject>(client, 'DELETE', path('ldap/user', name));
}

///////////////////////////////////////////////////////////////////////////////
// GROUPS

// listGroups returns a page of the groups, or a user's
export async function listGroups(client: Client, req: GroupListRequest = {}, signal?: AbortSignal): Promise<ObjectList> {
    return request<ObjectList>(client, 'GET', withQuery('ldap/group', req), { signal });
}

// getGroup returns the group with the name
export async function getGroup(client: Client, name: string): Promise<LdapObject> {
    return request<LdapObject>(client, 'GET', path('ldap/group', name));
}

// createGroup creates a group with the name, and the attributes
export async function createGroup(client: Client, name: string, attrs: Attrs = {}): Promise<LdapObject> {
    return request<LdapObject>(client, 'PUT', path('ldap/group', name), { body: { attrs } });
}

// updateGroup replaces the group's attributes with values, and deletes
// those with none. Changing its cn renames it.
export async function updateGroup(client: Client, name: string, attrs: Attrs): Promise<LdapObject> {
    return request<LdapObject>(client, 'PATCH', path('ldap/group', name), { body: { attrs } });
}

// deleteGroup deletes the group, and returns it, as it was
export async function deleteGroup(client: Client, name: string): Promise<LdapObject> {
    return request<LdapObject>(client, 'DELETE', path('ldap/group', name));
}

// addGroupUsers adds the users, by name, to the group, and returns it
export async function addGroupUsers(client: Client, group: string, users: readonly string[]): Promise<LdapObject> {
    return request<LdapObject>(client, 'POST', path('ldap/group', group, 'user'), { body: users });
}

// removeGroupUsers removes the users, by name, from the group, and returns
// it
export async function removeGroupUsers(client: Client, group: string, users: readonly string[]): Promise<LdapObject> {
    return request<LdapObject>(client, 'DELETE', path('ldap/group', group, 'user'), { body: users });
}

///////////////////////////////////////////////////////////////////////////////
// OBJECTS

// listObjects returns a page of the entries under the base DN, or the
// prefix, or only those directly under it, with children
export async function listObjects(client: Client, req: ObjectListRequest = {}, signal?: AbortSignal): Promise<ObjectList> {
    return request<ObjectList>(client, 'GET', withQuery('ldap/object', req), { signal });
}

// getObject returns the entry, whose DN is under the base DN, or relative to
// it
export async function getObject(client: Client, dn: string): Promise<LdapObject> {
    return request<LdapObject>(client, 'GET', path('ldap/object', dn));
}

// createObject creates the entry, with the attributes, which need an
// objectClass
export async function createObject(client: Client, dn: string, attrs: Attrs): Promise<LdapObject> {
    return request<LdapObject>(client, 'PUT', path('ldap/object', dn), { body: { attrs } });
}

// updateObject replaces the entry's attributes with values, and deletes
// those with none. Changing a value of its RDN renames it.
export async function updateObject(client: Client, dn: string, attrs: Attrs): Promise<LdapObject> {
    return request<LdapObject>(client, 'PATCH', path('ldap/object', dn), { body: { attrs } });
}

// deleteObject deletes the entry, which has no children, and returns it, as
// it was
export async function deleteObject(client: Client, dn: string): Promise<LdapObject> {
    return request<LdapObject>(client, 'DELETE', path('ldap/object', dn));
}

// bindObject checks the entry's password, which is sent as plain text, and
// returns the entry. A wrong password is a 401.
export async function bindObject(client: Client, dn: string, password: string): Promise<LdapObject> {
    const response = await (client.fetch ?? fetch)(url(client.base, path('ldap/object', dn, 'bind')), {
        method: 'POST',
        headers: { Accept: 'application/json', 'Content-Type': 'text/plain' },
        body: password,
    });
    if (!response.ok) {
        throw await errorResponse(response);
    }
    return (await response.json()) as LdapObject;
}

// changePassword changes the entry's password, with the old one, or resets
// it, without, and returns the entry, with the password, when it's
// generated
export async function changePassword(client: Client, dn: string, req: PasswordRequest = {}): Promise<PasswordResponse> {
    return request<PasswordResponse>(client, 'POST', path('ldap/object', dn, 'password'), { body: req });
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// path joins the path with its segments, escaped, so a DN with a slash is
// one segment
export function path(base: string, ...segments: string[]): string {
    return [base, ...segments.map((segment) => encodeURIComponent(segment))].join('/');
}

// withQuery returns the path with the request's query, which repeats the
// values of a list, such as attr, and leaves out those which aren't set
export function withQuery(base: string, req: object): string {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(req)) {
        if (Array.isArray(value)) {
            for (const item of value) {
                params.append(key, String(item));
            }
        } else if (value !== undefined && value !== null && value !== '') {
            params.set(key, String(value));
        }
    }
    const search = params.toString();
    return search ? `${base}?${search}` : base;
}
