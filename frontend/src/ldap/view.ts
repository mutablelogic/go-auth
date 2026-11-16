// The LDAP module's elements, which need lit, and Carbon's web components:
//
// - ga-ldap-users is the Users page.
// - ga-ldap-page is a page of the module which isn't made yet, with a
//   header of the directory's status: whether it's connected, its host, and
//   the user it binds as.
// - ldapModule adds the module to the app: its LDAP item in the app's menu
//   bar, and its sidebar, of Users, Groups, Objects and Schema, while it's
//   active. Users and Groups are only when the directory has them.

import { html } from 'lit';
import type { Client } from '@mutablelogic/go-server/api';
import type { ChangesController } from '@mutablelogic/go-server/broadcaster';
import type { NavController } from '@mutablelogic/go-server/nav';
import type { NotificationController } from '@mutablelogic/go-server/notification';
import type { Router } from '@mutablelogic/go-server/router';
import { LdapStatusController } from './controller.ts';
import { LdapPage } from './parts.ts';
import type { LdapStatus } from './schema.ts';
import { LdapUsersElement, LdapUsersTag } from './users.ts';

export { LdapPage, attrsView, entryFormView, secretView, statusView } from './parts.ts';
export { LdapUsersElement, LdapUsersTag, passwordFormView, userColumns } from './users.ts';

// Carbon components
import '@mutablelogic/go-server/page/view';
import UsersIcon from '@carbon/icons/es/user--multiple/32.js';
import GroupsIcon from '@carbon/icons/es/events/32.js';
import ObjectsIcon from '@carbon/icons/es/tree-view--alt/32.js';
import SchemaIcon from '@carbon/icons/es/catalog/32.js';

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

export const LdapPageTag = 'ga-ldap-page';

// LdapPageKind is which of the module's pages a page is
export type LdapPageKind = 'users' | 'groups' | 'objects' | 'schema';

// The pages' headings, icons and ids, which they're routed to
const pages: Record<LdapPageKind, { heading: string; icon: unknown; id: string }> = {
    users: { heading: 'Users', icon: UsersIcon, id: 'ldap-users' },
    groups: { heading: 'Groups', icon: GroupsIcon, id: 'ldap-groups' },
    objects: { heading: 'Objects', icon: ObjectsIcon, id: 'ldap-objects' },
    schema: { heading: 'Schema', icon: SchemaIcon, id: 'ldap-schema' },
};

///////////////////////////////////////////////////////////////////////////////
// PAGE

// LdapPageElement is a page of the module which isn't made yet, with a
// header of the directory's status, which follows its connection
export class LdapPageElement extends LdapPage {
    static override properties = {
        ...LdapPage.properties,
        kind: { type: String },
    };

    declare kind: LdapPageKind;

    constructor() {
        super();
        this.kind = 'objects';
    }

    protected override render() {
        const page = pages[this.kind];
        return html`<gs-page-header heading=${page.heading} .icon=${page.icon} .details=${this.details}></gs-page-header>`;
    }
}

if (!customElements.get(LdapPageTag)) {
    customElements.define(LdapPageTag, LdapPageElement);
}

declare global {
    interface HTMLElementTagNameMap {
        [LdapPageTag]: LdapPageElement;
    }
}

///////////////////////////////////////////////////////////////////////////////
// MODULE

// LdapApp is what the module needs of the app which includes it: its
// navigation, its router, the LDAP API's client, its notifications and
// changes, the element its pages are added to, and the directory's status,
// from configSection(config, 'ldap')
export interface LdapApp {
    nav: NavController;
    router: Router;
    client: Client;
    root: HTMLElement;
    status: LdapStatus;
    notifications?: NotificationController;
    changes?: ChangesController;
}

// LdapPages are the module's pages, with the status they follow
export interface LdapPages {
    status: LdapStatusController;
    users?: LdapUsersElement;
    groups?: LdapPageElement;
    objects: LdapPageElement;
    schema: LdapPageElement;
}

// ldapModule adds the LDAP module to the app: its section, which owns the
// menu bar's LDAP item, and the sidebar while it's active, of its pages,
// which it adds to the root, and routes to. Users and Groups are only when
// the directory has them. The pages' ids are prefixed with page-, not the
// hashes they're routed to, so the browser doesn't scroll to them.
export function ldapModule(app: LdapApp, section = 'LDAP'): LdapPages {
    const status = new LdapStatusController(app.status, app.changes);
    const add = <E extends LdapPage>(kind: LdapPageKind, element: E): E => {
        const page = document.createElement('section');
        page.id = `page-${pages[kind].id}`;
        page.className = 'page';
        page.hidden = true;

        element.status = status;
        element.client = app.client;
        element.notifications = app.notifications;
        element.changes = app.changes;
        page.append(element);
        app.root.append(page);
        app.router.add(pages[kind].id, page);
        return element;
    };
    const placeholder = (kind: LdapPageKind) => {
        const element = document.createElement(LdapPageTag);
        element.kind = kind;
        return add(kind, element);
    };

    const kinds: LdapPageKind[] = [];
    if (app.status.user_dn) {
        kinds.push('users');
    }
    if (app.status.group_dn) {
        kinds.push('groups');
    }
    kinds.push('objects', 'schema');

    const result: LdapPages = {
        status,
        users: app.status.user_dn ? add('users', document.createElement(LdapUsersTag)) : undefined,
        groups: app.status.group_dn ? placeholder('groups') : undefined,
        objects: placeholder('objects'),
        schema: placeholder('schema'),
    };
    app.nav.setSection(section, kinds.map((kind) => ({ id: pages[kind].id, label: pages[kind].heading, href: `#${pages[kind].id}` })));
    return result;
}
