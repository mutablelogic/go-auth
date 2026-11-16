// The LDAP module's controllers: the directory's status, which follows its
// connection, the users and groups, a page at a time, in ListControllers,
// which gs-tables show, the entries under a DN, for a tree, and the
// directory's schema

import type { Client } from '@mutablelogic/go-server/api';
import type { Change, ChangeFilter, ChangesController } from '@mutablelogic/go-server/broadcaster';
import { ListController } from '@mutablelogic/go-server/list';
import type { NotificationController } from '@mutablelogic/go-server/notification';
import { entrySchema, type EntryKind, type EntrySchema } from './form.ts';
import * as api from './httpclient.ts';
import {
    ChangeSchema, TableConnection, TableGroup, TableObject, TableUser, rdnValue, sameDN, searchFilter,
    type AttributeType, type LdapObject, type LdapStatus, type ObjectClass,
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
    // without one, with their object classes, in the directory's order
    async children(dn?: string, signal?: AbortSignal): Promise<LdapObject[]> {
        const result: LdapObject[] = [];
        for (let offset = 0; ; ) {
            const page = await api.listObjects(this.client, { prefix: dn || undefined, children: true, attr: ['objectClass'], offset, limit: 500 }, signal);
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

// loadEntrySchema returns the schema of users, or groups: the object
// classes they're created with, and those they inherit from, and the
// directory's attribute types, every page of them
export async function loadEntrySchema(client: Client, kind: EntryKind, signal?: AbortSignal): Promise<EntrySchema> {
    const classes = await api.listObjectClasses(client, { for: kind, limit: 1000 }, signal);
    const types: AttributeType[] = [];
    for (let offset = 0; ; ) {
        const page = await api.listAttributeTypes(client, { offset, limit: 1000 }, signal);
        types.push(...(page.body ?? []));
        offset += page.body?.length ?? 0;
        if (!page.body?.length || offset >= page.count) {
            break;
        }
    }
    return entrySchema(kind, classes.body ?? [], types);
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// filter is the changes of the table, in the LDAP schema, with the action
function filter(table: string, action?: 'create' | 'update' | 'delete'): ChangeFilter {
    return { schema: ChangeSchema, table, action };
}
