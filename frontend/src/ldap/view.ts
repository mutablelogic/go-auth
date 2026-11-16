// The LDAP module's elements, which need lit, and Carbon's web components:
//
// - ga-ldap-users, ga-ldap-groups, ga-ldap-objects and ga-ldap-schema are
//   the Users, Groups, Objects and Schema pages, whose headers have the
//   directory's status: whether it's connected, its host, and the user it
//   binds as.
// - ldapModule adds the module to the app: its LDAP item in the app's menu
//   bar, and its sidebar, of Users, Groups, Objects and Schema, while it's
//   active. Users and Groups are only when the directory has them.

import type { Client } from '@mutablelogic/go-server/api';
import type { ChangesController } from '@mutablelogic/go-server/broadcaster';
import { configSection, getConfig } from '@mutablelogic/go-server/config';
import type { NavController } from '@mutablelogic/go-server/nav';
import type { NotificationController } from '@mutablelogic/go-server/notification';
import type { Router } from '@mutablelogic/go-server/router';
import { LdapStatusController } from './controller.ts';
import { LdapPage } from './parts.ts';
import type { LdapStatus } from './schema.ts';
import { LdapGroupsElement, LdapGroupsTag } from './groups.ts';
import { LdapObjectsElement, LdapObjectsTag } from './objects.ts';
import { LdapSchemaElement, LdapSchemaTag } from './schemapage.ts';
import { LdapUsersElement, LdapUsersTag } from './users.ts';

export { LdapPage, attrsView, entryFormView, secretView, statusView } from './parts.ts';
export { LdapUsersElement, LdapUsersTag, passwordFormView, userColumns } from './users.ts';
export { LdapGroupsElement, LdapGroupsTag, groupColumns } from './groups.ts';
export { LdapObjectsElement, LdapObjectsTag, entryColumns } from './objects.ts';
export { LdapSchemaElement, LdapSchemaTag, attributeColumns, classColumns, type SchemaTab } from './schemapage.ts';


///////////////////////////////////////////////////////////////////////////////
// GLOBALS

// LdapPageKind is which of the module's pages a page is
export type LdapPageKind = 'users' | 'groups' | 'objects' | 'schema';

// The pages' headings, and ids, which they're routed to
const pages: Record<LdapPageKind, { heading: string; id: string }> = {
    users: { heading: 'Users', id: 'ldap-users' },
    groups: { heading: 'Groups', id: 'ldap-groups' },
    objects: { heading: 'Objects', id: 'ldap-objects' },
    schema: { heading: 'Schema', id: 'ldap-schema' },
};

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
    // refreshStatus reads the status again, when changes may have been
    // missed, which is the configuration's ldap section, without it
    refreshStatus?: () => Promise<LdapStatus | undefined>;
}

// LdapPages are the module's pages, with the status they follow
export interface LdapPages {
    status: LdapStatusController;
    users?: LdapUsersElement;
    groups?: LdapGroupsElement;
    objects: LdapObjectsElement;
    schema: LdapSchemaElement;
}

// ldapModule adds the LDAP module to the app: its section, which owns the
// menu bar's LDAP item, and the sidebar while it's active, of its pages,
// which it adds to the root, and routes to. Users and Groups are only when
// the directory has them. The pages' ids are prefixed with page-, not the
// hashes they're routed to, so the browser doesn't scroll to them.
export function ldapModule(app: LdapApp, section = 'LDAP'): LdapPages {
    const status = new LdapStatusController(app.status, app.changes, app.refreshStatus ?? (() => getConfig().then((config) => configSection<LdapStatus>(config, 'ldap'))));
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
        groups: app.status.group_dn ? add('groups', document.createElement(LdapGroupsTag)) : undefined,
        objects: add('objects', document.createElement(LdapObjectsTag)),
        schema: add('schema', document.createElement(LdapSchemaTag)),
    };
    app.nav.setSection(section, kinds.map((kind) => ({ id: pages[kind].id, label: pages[kind].heading, href: `#${pages[kind].id}` })));
    return result;
}
