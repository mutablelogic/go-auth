// ga-ldap-groups is the LDAP module's Groups page: its header, with the
// directory's status, the table of groups, which is searched, and a panel,
// which opens a group, with its members and attributes, adds a user to it,
// or removes one, edits it, and deletes it

import { html, nothing, type PropertyValues } from 'lit';
import { until } from 'lit/directives/until.js';
import type { Column, TableActionError, TableSearch, TableToolbarAction } from '@mutablelogic/go-server/list/view';
import { PanelController, type PanelAction } from '@mutablelogic/go-server/panel';
import { GroupController, listAllUsers, loadEntrySchemas, type EntrySchemas } from './controller.ts';
import { entryAttrs, entryForm, entryFormErrors, type EntryFormErrors } from './form.ts';
import * as api from './httpclient.ts';
import { LdapPage, attrsView, entryFormView } from './parts.ts';
import { first, memberCount, rdnValue, sameDN, type LdapObject } from './schema.ts';

// go-server's and Carbon's elements
import '@mutablelogic/go-server/list/view';
import '@mutablelogic/go-server/page/view';
import '@mutablelogic/go-server/panel/view';
import '@carbon/web-components/es/components/button/index.js';
import '@carbon/web-components/es/components/combo-box/index.js';
import '@carbon/web-components/es/components/tag/index.js';
import AddIcon from '@carbon/icons/es/add/16.js';
import iconLoader from '@carbon/web-components/es/globals/internal/icon-loader.js';
import GroupsIcon from '@carbon/icons/es/events/32.js';

///////////////////////////////////////////////////////////////////////////////
// PARTS

// AddButton is the icon of a button which adds
const AddButton = iconLoader(AddIcon, { slot: 'icon' });

// groupColumns are the columns of a table of groups: the name, description,
// how many members it has, and its group ID, of a posixGroup
export const groupColumns: Column<LdapObject>[] = [
    { header: 'Name', cell: (group) => html`<code style="font-family: 'IBM Plex Mono', monospace; font-size: 0.875rem">${rdnValue(group.dn)}</code>` },
    { header: 'Description', cell: (group) => first(group, 'description') ?? '' },
    { header: 'Members', cell: (group) => String(memberCount(group)) },
    { header: 'GID', cell: (group) => first(group, 'gidNumber') ?? '' },
];

///////////////////////////////////////////////////////////////////////////////
// PAGE

export const LdapGroupsTag = 'ga-ldap-groups';

// Body is what the panel shows, and its kind, which says whether a form is
// open, so the panel isn't closed, or changed, when the list is loaded again
interface Body {
    kind: 'group' | 'form' | 'member';
    content: unknown;
    // dn is the group's, when it's one's
    dn?: string;
}

export class LdapGroupsElement extends LdapPage {
    static override properties = {
        ...LdapPage.properties,
        controller: { attribute: false },
        heading: { type: String },
        body: { state: true },
    };

    // controller keeps the groups, which is made with the client, when it
    // isn't given
    declare controller?: GroupController;
    declare heading: string;
    declare private body?: Body;

    private readonly panel = new PanelController<Body>();
    private unsubscribe?: () => void;

    // schemas are the groups' forms' object classes and attributes, loaded
    // when a form is first shown
    private schemas?: Promise<EntrySchemas>;

    // opened counts what's opened in the panel, so a response which arrives
    // after what it was for was closed, or another opened, is ignored
    private opened = 0;

    constructor() {
        super();
        this.heading = 'Groups';
        // Closing the panel discards what's still opening in it
        this.panel.onClose(() => {
            this.opened++;
            this.controller?.list.close();
        });
        this.panel.onError((error, action) => this.notifications?.error(`${action.label} didn't work`, error));
    }

    override connectedCallback(): void {
        super.connectedCallback();
        this.watch();
    }

    override disconnectedCallback(): void {
        this.unsubscribe?.();
        this.unsubscribe = undefined;
        super.disconnectedCallback();
    }

    protected override willUpdate(changed: PropertyValues<this>): void {
        if (!this.controller && this.client) {
            this.controller = new GroupController(this.client, { notifications: this.notifications, changes: this.changes });
        }
        if (changed.has('controller') || changed.has('client')) {
            this.watch();
        }
    }

    protected override render() {
        if (!this.controller) {
            return nothing;
        }
        const tools: TableToolbarAction[] = [{ label: 'Create a group', icon: AddIcon, run: () => this.edit() }];
        return html`
            <gs-page-header heading=${this.heading} .icon=${GroupsIcon} .details=${this.details}></gs-page-header>
            <gs-table .controller=${this.controller.list} .columns=${groupColumns} .itemKey=${(group: LdapObject) => group.dn.toLowerCase()}
                search="Search groups" .toolbarActions=${tools}
                @gs-table-search=${(event: CustomEvent<TableSearch>) => { void this.controller?.setSearch(event.detail.value).then(() => this.requestUpdate()); }}
                @gs-table-action-error=${(event: CustomEvent<TableActionError<LdapObject>>) => this.notifications?.error(`${event.detail.action.label} didn't work`, event.detail.error)}
                empty=${this.controller.search ? 'No groups match' : 'No groups'}></gs-table>
            <gs-panel .controller=${this.panel}>${this.body?.content ?? nothing}</gs-panel>
        `;
    }

    // watch opens a group in the panel when it's opened in the table, and
    // closes the panel when it's closed, unless a form is open
    private watch() {
        this.unsubscribe?.();
        this.unsubscribe = this.isConnected ? this.controller?.list.subscribe(({ selected }) => {
            if (selected) {
                if (!this.panel.isOpen || !this.body?.dn || !sameDN(this.body.dn, selected.dn) || this.body.kind === 'group') {
                    this.show(selected);
                }
            } else if (this.panel.isOpen && this.body?.kind === 'group') {
                this.panel.close();
            }
        }) : undefined;
    }

    // open shows the body in the panel, with its header and actions
    private open(title: string, subtitle: string, body: Body, actions: PanelAction[]) {
        this.opened++;
        this.body = body;
        this.panel.setHeader({ title, subtitle });
        this.panel.setActions(actions);
        this.panel.open(body);
    }

    // show shows a group's members and attributes, and what can be done
    // with it
    private show(group: LdapObject) {
        this.open(rdnValue(group.dn), first(group, 'description') ?? 'Group', {
            kind: 'group',
            dn: group.dn,
            content: html`${this.membersView(group)}${attrsView(group)}`,
        }, [
            { label: 'Delete', kind: 'danger', close: false, run: () => this.delete(group) },
            { label: 'Edit', kind: 'primary', close: false, run: () => this.edit(group) },
        ]);
    }

    // membersView is the group's members which are users, each of which is
    // removed when its tag is closed, when the manager has users
    private membersView(group: LdapObject): unknown {
        const client = this.client;
        if (!client || !this.current?.user_dn) {
            return nothing;
        }
        const name = rdnValue(group.dn);
        const members = listAllUsers(client, { group: name, attr: ['uid', 'cn'] });
        return until(members.then((found) => html`
            <p class="helper">${found.length ? 'Members' : 'It has no members'}</p>
            <div style="display: flex; flex-wrap: wrap; align-items: center; gap: 0.25rem; margin-bottom: 1rem">
                ${found.map((user) => {
                    const member = rdnValue(user.dn);
                    return html`<cds-dismissible-tag size="sm" text=${member} tag-title=${`Remove ${member} from ${name}`}
                        @cds-dismissible-tag-beingclosed=${(event: Event) => {
                            event.preventDefault();
                            void this.removeMember(group, member);
                        }}></cds-dismissible-tag>`;
                })}
                <cds-button kind="ghost" size="sm" @click=${() => this.addMember(group)}>Add a user${AddButton}</cds-button>
            </div>
        `, (error: unknown) => {
            this.notifications?.error(`${name}'s members couldn't be loaded`, error);
            return nothing;
        }), nothing);
    }

    // edit shows the form which creates a group, or edits one, from the
    // groups' object classes, or its own, once they're loaded, and shows it
    private async edit(group?: LdapObject) {
        if (!this.client) {
            return;
        }

        // A new group isn't the one selected, which the list would show
        // again in place of the form, when it's loaded again
        if (!group) {
            this.controller?.list.close();
        }
        const opened = this.opened;
        this.schemas ??= loadEntrySchemas(this.client, 'group');
        let schemas: EntrySchemas;
        try {
            schemas = await this.schemas;
        } catch (error) {
            // They're loaded again next time
            this.schemas = undefined;
            throw error;
        }
        if (this.opened !== opened) {
            return;
        }

        const form = entryForm(group ? schemas.of(group) : schemas.created, group);
        let errors: EntryFormErrors = {};
        const rerender = () => {
            this.body = { kind: 'form', dn: group?.dn, content: entryFormView(form, rerender, errors) };
        };
        const cancel: PanelAction = group
            ? { label: 'Cancel', kind: 'secondary', close: false, run: () => this.show(group) }
            : { label: 'Cancel', kind: 'secondary' };
        this.open(group ? `Edit ${rdnValue(group.dn)}` : 'Create a group', 'Group', {
            kind: 'form',
            dn: group?.dn,
            content: entryFormView(form, rerender, errors),
        }, [cancel, {
            label: group ? 'Save' : 'Create',
            kind: 'primary',
            close: false,
            run: async () => {
                errors = entryFormErrors(form);
                rerender();
                if (Object.keys(errors).length || !this.client) {
                    return;
                }
                const attrs = entryAttrs(form);
                if (!group) {
                    const created = await api.createGroup(this.client, form.name.trim(), attrs);
                    this.notifications?.push({ kind: 'success', title: `${rdnValue(created.dn)} was created` });
                    this.select(created);
                } else if (Object.keys(attrs).length) {
                    const updated = await api.updateGroup(this.client, rdnValue(group.dn), attrs);
                    this.notifications?.push({ kind: 'success', title: `${rdnValue(updated.dn)} was changed` });
                    this.select(updated);
                } else {
                    this.notifications?.push({ kind: 'info', title: 'Nothing was changed' });
                    this.show(group);
                }
            },
        }]);
    }

    // select opens the group in the list, which shows it, so the list's
    // selection is the group the panel shows, such as a new, or renamed, one
    private select(group: LdapObject) {
        this.controller?.list.open(group);
        // The list shows it, unless it was already selected
        if (this.body?.kind !== 'group' || !this.body.dn || !sameDN(this.body.dn, group.dn)) {
            this.show(group);
        }
    }

    // addMember shows the users who can be added to the group, and adds the
    // one chosen
    private addMember(group: LdapObject) {
        const client = this.client;
        if (!client) {
            return;
        }
        const name = rdnValue(group.dn);
        const state = { user: '' };
        const choices = Promise.all([
            listAllUsers(client, { attr: ['uid', 'cn'] }),
            listAllUsers(client, { group: name, attr: ['uid', 'cn'] }),
        ]).then(([all, members]) => {
            const dns = members.map((user) => user.dn);
            return all.filter((user) => !dns.some((dn) => sameDN(dn, user.dn))).map((user) => rdnValue(user.dn));
        });
        const view = (error?: string) => html`
            <div class="form">
                ${until(choices.then((users) => users.length ? html`
                    <cds-combo-box title-text="User" helper-text="Type to filter the users" ?invalid=${!!error} invalid-text=${error ?? ''}
                        @cds-combo-box-selected=${(event: Event) => { state.user = (event.target as HTMLInputElement).value ?? ''; }}>
                        ${users.map((user) => html`<cds-combo-box-item value=${user}>${user}</cds-combo-box-item>`)}
                    </cds-combo-box>
                ` : html`<p class="helper">Every user is a member.</p>`, (err: unknown) => {
                    this.notifications?.error("The users couldn't be loaded", err);
                    return nothing;
                }), nothing)}
            </div>
        `;
        this.open(`Add a user to ${name}`, 'Group', { kind: 'member', dn: group.dn, content: view() }, [
            { label: 'Cancel', kind: 'secondary', close: false, run: () => this.show(group) },
            {
                label: 'Add',
                kind: 'primary',
                close: false,
                run: async () => {
                    if (!state.user) {
                        this.body = { kind: 'member', dn: group.dn, content: view('Choose a user') };
                        return;
                    }
                    const updated = await api.addGroupUsers(client, name, [state.user]);
                    this.notifications?.push({ kind: 'success', title: `${state.user} was added to ${name}` });
                    this.show(updated);
                },
            },
        ]);
    }

    // removeMember removes the user from the group, and shows it again,
    // when it's still shown
    private async removeMember(group: LdapObject, user: string) {
        const name = rdnValue(group.dn);
        if (!this.client || !confirm(`Remove ${user} from ${name}?`)) {
            return;
        }
        const opened = this.opened;
        let updated: LdapObject;
        try {
            updated = await api.removeGroupUsers(this.client, name, [user]);
        } catch (error) {
            this.notifications?.error(`${user} couldn't be removed from ${name}`, error);
            return;
        }
        this.notifications?.push({ kind: 'success', title: `${user} was removed from ${name}` });
        if (this.opened === opened && this.panel.isOpen) {
            this.show(updated);
        }
    }

    // delete deletes a group, once it's confirmed
    private async delete(group: LdapObject) {
        const name = rdnValue(group.dn);
        if (!this.client || !confirm(`Delete ${name}? Its members stay, without it.`)) {
            return;
        }
        await api.deleteGroup(this.client, name);
        this.notifications?.push({ kind: 'success', title: `${name} was deleted` });
        this.panel.close();
    }
}

if (!customElements.get(LdapGroupsTag)) {
    customElements.define(LdapGroupsTag, LdapGroupsElement);
}

declare global {
    interface HTMLElementTagNameMap {
        [LdapGroupsTag]: LdapGroupsElement;
    }
}
