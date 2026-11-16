// The LDAP module's elements, which need lit, and Carbon's web components:
//
// - ga-ldap-page is a page of the module, with a header of the directory's
//   status: whether it's connected, its host, and the user it binds as.
// - ldapModule adds the module to the app: its LDAP item in the app's menu
//   bar, and its sidebar, of Users, Groups, Objects and Schema, while it's
//   active. Users and Groups are only when the directory has them.

import { LitElement, html, nothing, type TemplateResult } from 'lit';
import type { Client } from '@mutablelogic/go-server/api';
import type { ChangesController } from '@mutablelogic/go-server/broadcaster';
import type { NavController } from '@mutablelogic/go-server/nav';
import type { NotificationController } from '@mutablelogic/go-server/notification';
import type { Router } from '@mutablelogic/go-server/router';
import { LdapStatusController } from './controller.ts';
import type { LdapStatus } from './schema.ts';

// Carbon components
import '@mutablelogic/go-server/page/view';
import '@carbon/web-components/es/components/tag/index.js';
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

// LdapPageElement is a page of the module, with a header of the directory's
// status, which follows its connection
export class LdapPageElement extends LitElement {
    static override properties = {
        kind: { type: String },
        status: { attribute: false },
        client: { attribute: false },
        notifications: { attribute: false },
        changes: { attribute: false },
        current: { state: true },
    };

    kind: LdapPageKind = 'users';
    status?: LdapStatusController;
    client?: Client;
    notifications?: NotificationController;
    changes?: ChangesController;
    private current?: LdapStatus;
    private unsubscribe?: () => void;

    // The page is in the light DOM, as the certificate pages are, so Carbon's
    // styles, such as the header's theme, apply to it
    protected override createRenderRoot(): HTMLElement {
        return this;
    }

    override connectedCallback(): void {
        super.connectedCallback();
        this.unsubscribe = this.status?.subscribe((status) => {
            this.current = status;
        });
    }

    override disconnectedCallback(): void {
        this.unsubscribe?.();
        this.unsubscribe = undefined;
        super.disconnectedCallback();
    }

    protected override render() {
        const page = pages[this.kind];
        return html`
            <gs-page-header heading=${page.heading} .icon=${page.icon} .details=${this.current ? statusView(this.current) : nothing}></gs-page-header>
        `;
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

// statusView is the directory's status: whether it's connected, its host
// and port, and the user it binds as
export function statusView(status: LdapStatus): TemplateResult {
    return html`
        <span style="display: inline-flex; align-items: center; gap: 0.5rem">
            ${status.connected
                ? html`<cds-tag type="green" size="sm">Connected</cds-tag>`
                : html`<cds-tag type="red" size="sm">Disconnected</cds-tag>`}
            <span>${status.host}:${status.port}, as ${status.user}</span>
        </span>
    `;
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
    users?: LdapPageElement;
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
    const add = (kind: LdapPageKind) => {
        const page = document.createElement('section');
        page.id = `page-${pages[kind].id}`;
        page.className = 'page';
        page.hidden = true;

        const element = document.createElement(LdapPageTag);
        element.kind = kind;
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

    const result: LdapPages = { status, objects: undefined!, schema: undefined! };
    for (const kind of kinds) {
        result[kind] = add(kind);
    }
    app.nav.setSection(section, kinds.map((kind) => ({ id: pages[kind].id, label: pages[kind].heading, href: `#${pages[kind].id}` })));
    return result;
}
