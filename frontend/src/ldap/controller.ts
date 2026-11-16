// The LDAP module's controllers: the directory's status, which follows its
// connection, the users and groups, a page at a time, in ListControllers,
// which gs-tables show, the entries under a DN, for a tree, and the
// directory's schema

import type { Client } from '@mutablelogic/go-server/api';
import type { Change, ChangeFilter, ChangesController } from '@mutablelogic/go-server/broadcaster';
import { ListController } from '@mutablelogic/go-server/list';
import type { NotificationController } from '@mutablelogic/go-server/notification';
import { classClosure, entrySchema, type EntryKind, type EntrySchema } from './form.ts';
import * as api from './httpclient.ts';
import {
    ChangeSchema, TableConnection, TableGroup, TableObject, TableUser, rdn, rdnValue, sameDN, searchFilter,
    values, type GroupListRequest, type UserListRequest, type LdapObject, type LdapStatus, type ObjectClass, type AttributeType,
} from './schema.ts';

// LdapOptions are the controllers' notifications, which say why entries
// can't be loaded, and the changes, which load them again
export interface LdapOptions {
    notifications?: NotificationController;
    changes?: ChangesController;
    pageSize?: number;
}

// The attributes a search of users and groups looks in
export const UserSearch = ['uid', 'cn', 'mail', 'sn', 'givenName'] as const;
export const GroupSearch = ['cn', 'description'] as const;

///////////////////////////////////////////////////////////////////////////////
// STATUS

// LdapStatusController is the directory's status, from the configuration,
// and whether the manager is connected, which follows the connection's
// changes, as it comes up or goes down
export class LdapStatusController {
    private state: LdapStatus;
    private readonly listeners = new Set<(status: LdapStatus) => void>();

    // refresh reads the status again, such as from the configuration, when
    // changes may have been missed, as when the changes' stream starts
    constructor(status: LdapStatus, changes?: ChangesController, refresh?: () => Promise<LdapStatus | undefined>) {
        this.state = { ...status };
        changes?.on(filter(TableConnection), (change?: Change) => {
            if (change?.action === 'create' || change?.action === 'delete') {
                this.update({ ...this.state, connected: change.action === 'create' });
            } else if (!change && refresh) {
                refresh().then((status) => status && this.update(status), () => {
                    // The status is kept until it can be read
                });
            }
        });
    }

    // current is the status, as it is now
    get current(): LdapStatus {
        return this.state;
    }

    // subscribe calls fn with the status, now, and when it changes, until
    // it's unsubscribed
    subscribe(fn: (status: LdapStatus) => void): () => void {
        this.listeners.add(fn);
        fn(this.state);
        return () => this.listeners.delete(fn);
    }

    // update changes the status, such as when the configuration is read
    // again, and tells the listeners
    update(status: LdapStatus): void {
        this.state = { ...status };
        for (const fn of this.listeners) {
            fn(this.state);
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// USERS AND GROUPS

// UserController keeps the users, or a group's members, a page at a time,
// whose names, mail, and so on, have the search's text
export class UserController {
    readonly client: Client;
    readonly list: ListController<LdapObject>;
    private query = '';
    private group?: string;

    constructor(client: Client, options: LdapOptions = {}) {
        this.client = client;
        this.list = new ListController<LdapObject>({
            name: 'Users',
            list: async (offset, limit) => {
                const page = await api.listUsers(client, { offset, limit, filter: searchFilter(this.query, UserSearch), group: this.group });
                return { count: page.count, body: page.body ?? [] };
            },
            get: (user) => api.getUser(client, rdnValue(user.dn)),
            same: (a, b) => sameDN(a.dn, b.dn),
            notifications: options.notifications,
            changes: options.changes,
            // A group's change, such as its members, changes its members
            filter: options.changes ? [filter(TableUser), filter(TableGroup), filter(TableObject), filter(TableConnection, 'create')] : undefined,
            pageSize: options.pageSize,
        });
    }

    // search is the text the users are searched for
    get search(): string {
        return this.query;
    }

    // setSearch lists the users with the text, or all of them, without, from
    // the first page
    setSearch(text: string): Promise<void> {
        this.query = text.trim();
        return this.list.reset();
    }

    // setGroup lists only the group's members, or all the users, without one
    setGroup(group?: string): Promise<void> {
        this.group = group || undefined;
        return this.list.reset();
    }
}

// GroupController keeps the groups, or a user's, a page at a time, whose
// names or descriptions have the search's text
export class GroupController {
    readonly client: Client;
    readonly list: ListController<LdapObject>;
    private query = '';
    private user?: string;

    constructor(client: Client, options: LdapOptions = {}) {
        this.client = client;
        this.list = new ListController<LdapObject>({
            name: 'Groups',
            list: async (offset, limit) => {
                const page = await api.listGroups(client, { offset, limit, filter: searchFilter(this.query, GroupSearch), user: this.user });
                return { count: page.count, body: page.body ?? [] };
            },
            get: (group) => api.getGroup(client, rdnValue(group.dn)),
            same: (a, b) => sameDN(a.dn, b.dn),
            notifications: options.notifications,
            changes: options.changes,
            // A user's change, such as its uid, changes which groups it's in
            filter: options.changes ? [filter(TableGroup), filter(TableUser), filter(TableObject), filter(TableConnection, 'create')] : undefined,
            pageSize: options.pageSize,
        });
    }

    get search(): string {
        return this.query;
    }

    // setSearch lists the groups with the text, or all of them, without, from
    // the first page
    setSearch(text: string): Promise<void> {
        this.query = text.trim();
        return this.list.reset();
    }

    // setUser lists only the user's groups, or all the groups, without one
    setUser(user?: string): Promise<void> {
        this.user = user || undefined;
        return this.list.reset();
    }
}

///////////////////////////////////////////////////////////////////////////////
// OBJECTS

// ObjectController loads the entries directly under a DN, for a tree, and
// says when entries change, so a tree loads those it shows again
export class ObjectController {
    readonly client: Client;
    private readonly listeners = new Set<() => void>();

    constructor(client: Client, options: LdapOptions = {}) {
        this.client = client;
        // Changes which arrive together are one, the last, so which entries
        // changed isn't known, and any change is all of them
        options.changes?.on([filter(TableObject), filter(TableUser), filter(TableGroup), filter(TableConnection, 'create')], () => this.changed());
    }

    // children returns the entries directly under the DN, or the base DN,
    // without one, with their object classes, and whether they have children,
    // when the directory says, in its order
    async children(dn?: string, signal?: AbortSignal): Promise<LdapObject[]> {
        const result: LdapObject[] = [];
        for (let offset = 0; ; ) {
            const page = await api.listObjects(this.client, { prefix: dn || undefined, children: true, attr: ['objectClass', 'hasSubordinates'], offset, limit: 500 }, signal);
            result.push(...(page.body ?? []));
            offset += page.body?.length ?? 0;
            if (!page.body?.length || offset >= page.count) {
                return result;
            }
        }
    }

    // get returns the entry, with its attributes
    get(dn: string): Promise<LdapObject> {
        return api.getObject(this.client, dn);
    }

    // onChange calls fn when entries change, until it's unsubscribed
    onChange(fn: () => void): () => void {
        this.listeners.add(fn);
        return () => this.listeners.delete(fn);
    }

    private changed(): void {
        for (const fn of this.listeners) {
            fn();
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// SCHEMA

// SchemaController keeps the directory's object classes and attribute
// types, a page at a time, by name, whose names or OIDs are the search's
export class SchemaController {
    readonly classes: ListController<ObjectClass>;
    readonly attributes: ListController<AttributeType>;
    private classQuery = '';
    private attributeQuery = '';

    constructor(client: Client, options: LdapOptions = {}) {
        this.classes = new ListController<ObjectClass>({
            name: 'Object classes',
            list: async (offset, limit) => {
                const page = await api.listObjectClasses(client, { offset, limit, filter: this.classQuery || undefined });
                return { count: page.count, body: page.body ?? [] };
            },
            same: (a, b) => a.numericOid === b.numericOid,
            notifications: options.notifications,
            pageSize: options.pageSize,
        });
        this.attributes = new ListController<AttributeType>({
            name: 'Attribute types',
            list: async (offset, limit) => {
                const page = await api.listAttributeTypes(client, { offset, limit, filter: this.attributeQuery || undefined });
                return { count: page.count, body: page.body ?? [] };
            },
            same: (a, b) => a.numericOid === b.numericOid,
            notifications: options.notifications,
            pageSize: options.pageSize,
        });
    }

    // setClassSearch and setAttributeSearch list those with the name or OID,
    // or all of them, without one
    setClassSearch(text: string): Promise<void> {
        this.classQuery = text.trim();
        return this.classes.reset();
    }

    setAttributeSearch(text: string): Promise<void> {
        this.attributeQuery = text.trim();
        return this.attributes.reset();
    }
}

///////////////////////////////////////////////////////////////////////////////
// ENTRY SCHEMA

// EntrySchemas are the schemas of users', or groups', forms: a new one's,
// from the classes they're created with, and an existing one's, from its
// own object classes, which can be others
export interface EntrySchemas {
    created: EntrySchema;
    of(entry: LdapObject): EntrySchema;
    // classes are the directory's object classes, and create returns the
    // schema of a new entry of the classes, and those they inherit from,
    // named by the attribute
    classes: ObjectClass[];
    create(classes: readonly string[], naming?: string): EntrySchema;
}

// loadEntrySchemas returns the schemas of users', or groups', forms, from
// the classes they're created with, the directory's object classes, and its
// attribute types, every page of them
export async function loadEntrySchemas(client: Client, kind: EntryKind, signal?: AbortSignal): Promise<EntrySchemas> {
    // Any entry has no classes it's created with, which are chosen
    const [created, classes, types] = await Promise.all([
        kind === 'entry' ? [] : listAll((offset, limit) => api.listObjectClasses(client, { for: kind, offset, limit }, signal)),
        listAll((offset, limit) => api.listObjectClasses(client, { offset, limit }, signal)),
        listAll((offset, limit) => api.listAttributeTypes(client, { offset, limit }, signal)),
    ]);
    return {
        created: entrySchema(kind, created, types),
        // An existing entry is named by its RDN's attribute
        of: (entry) => entrySchema(kind, classClosure(classes, values(entry, 'objectClass').filter((v): v is string => typeof v === 'string')), types, rdnAttr(entry.dn)),
        classes,
        create: (names, naming) => entrySchema(kind, classClosure(classes, names), types, naming),
    };
}

// listAllGroups returns every group which matches the request, every page
// of them
export function listAllGroups(client: Client, req: GroupListRequest = {}, signal?: AbortSignal): Promise<LdapObject[]> {
    return listAll((offset, limit) => api.listGroups(client, { ...req, offset, limit }, signal));
}

// rdnAttr returns the attribute of the DN's RDN, such as uid
function rdnAttr(dn: string): string | undefined {
    const value = rdn(dn);
    const equals = value.indexOf('=');
    return equals < 0 ? undefined : value.slice(0, equals).trim();
}

// listAllUsers returns every user which matches the request, every page of
// them
export function listAllUsers(client: Client, req: UserListRequest = {}, signal?: AbortSignal): Promise<LdapObject[]> {
    return listAll((offset, limit) => api.listUsers(client, { ...req, offset, limit }, signal));
}

// listAll returns the items of every page, from the first, until there are
// as many as the count, or a page is empty
export async function listAll<T>(page: (offset: number, limit: number) => Promise<{ count: number; body?: T[] }>): Promise<T[]> {
    const result: T[] = [];
    for (;;) {
        const next = await page(result.length, 1000);
        result.push(...(next.body ?? []));
        if (!next.body?.length || result.length >= next.count) {
            return result;
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// filter is the changes of the table, in the LDAP schema, with the action
function filter(table: string, action?: 'create' | 'update' | 'delete'): ChangeFilter {
    return { schema: ChangeSchema, table, action };
}
