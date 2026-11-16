// The LDAP module's controllers: the directory's status, which follows its
// connection, the users and groups, a page at a time, in ListControllers,
// which gs-tables show, the entries under a DN, for a tree, and the
// directory's schema

import type { Client } from '@mutablelogic/go-server/api';
import type { Change, ChangeFilter, ChangesController } from '@mutablelogic/go-server/broadcaster';
import { ListController } from '@mutablelogic/go-server/list';
import type { NotificationController } from '@mutablelogic/go-server/notification';
import * as api from './httpclient.ts';
import {
    ChangeSchema, TableConnection, TableGroup, TableObject, TableUser, parentDN, rdnValue, sameDN, searchFilter,
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

    constructor(status: LdapStatus, changes?: ChangesController) {
        this.state = { ...status };
        changes?.on(filter(TableConnection), (change?: Change) => {
            if (change?.action === 'create' || change?.action === 'delete') {
                this.update({ ...this.state, connected: change.action === 'create' });
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
            get: (user) => api.getUser(client, rdnValue(user.dn)).catch(() => user),
            same: (a, b) => sameDN(a.dn, b.dn),
            notifications: options.notifications,
            changes: options.changes,
            filter: options.changes ? [filter(TableUser), filter(TableObject), filter(TableConnection, 'create')] : undefined,
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
            get: (group) => api.getGroup(client, rdnValue(group.dn)).catch(() => group),
            same: (a, b) => sameDN(a.dn, b.dn),
            notifications: options.notifications,
            changes: options.changes,
            filter: options.changes ? [filter(TableGroup), filter(TableObject), filter(TableConnection, 'create')] : undefined,
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
// says which DN's children change, so a tree loads them again
export class ObjectController {
    readonly client: Client;
    private readonly listeners = new Set<(parent: string) => void>();

    constructor(client: Client, options: LdapOptions = {}) {
        this.client = client;
        options.changes?.on([filter(TableObject), filter(TableUser), filter(TableGroup)], (change?: Change) => {
            // An entry's change is its parent's, and a rename's is also the
            // parent of what it was
            if (change?.table === TableObject && change.row) {
                this.changed(parentDN(change.row));
                const previous = (change.data as { previous?: string } | undefined)?.previous;
                if (previous && !sameDN(parentDN(previous), parentDN(change.row))) {
                    this.changed(parentDN(previous));
                }
            } else {
                // A user's or group's is by its name, so its parent isn't known
                this.changed('');
            }
        });
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

    // onChange calls fn with the DN whose children changed, which is empty
    // when it isn't known, until it's unsubscribed
    onChange(fn: (parent: string) => void): () => void {
        this.listeners.add(fn);
        return () => this.listeners.delete(fn);
    }

    private changed(parent: string): void {
        for (const fn of this.listeners) {
            fn(parent);
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
// PRIVATE METHODS

// filter is the changes of the table, in the LDAP schema, with the action
function filter(table: string, action?: 'create' | 'update' | 'delete'): ChangeFilter {
    return { schema: ChangeSchema, table, action };
}
