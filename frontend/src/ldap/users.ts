// ga-ldap-users is the LDAP module's Users page: its header, with the
// directory's status, the table of users, which is searched, and a panel,
// which opens a user, with its attributes and groups, edits it, adds it to
// a group, or removes it from one, sets its password, and deletes it

import { html, nothing, type PropertyValues, type TemplateResult } from 'lit';
import { live } from 'lit/directives/live.js';
import { until } from 'lit/directives/until.js';
import type { Column, TableActionError, TableSearch, TableToolbarAction } from '@mutablelogic/go-server/list/view';
import { PanelController, type PanelAction } from '@mutablelogic/go-server/panel';
import { UserController } from './controller.ts';
import { listAllGroups, loadEntrySchemas, type EntrySchemas } from './controller.ts';
import { entryAttrs, entryForm, entryFormErrors, passwordForm, passwordFormErrors, passwordRequest, type EntryFormErrors, type PasswordForm, type PasswordFormErrors } from './form.ts';
import * as api from './httpclient.ts';
import { LdapPage, attrsView, entryFormView, secretView } from './parts.ts';
import { first, rdnValue, sameDN, type LdapObject } from './schema.ts';

// go-server's and Carbon's elements
import '@mutablelogic/go-server/list/view';
import '@mutablelogic/go-server/page/view';
import '@mutablelogic/go-server/panel/view';
import '@carbon/web-components/es/components/checkbox/index.js';
import '@carbon/web-components/es/components/combo-box/index.js';
import '@carbon/web-components/es/components/password-input/index.js';
import '@carbon/web-components/es/components/tag/index.js';
import '@carbon/web-components/es/components/text-input/index.js';
import '@carbon/web-components/es/components/button/index.js';
import AddIcon from '@carbon/icons/es/add/16.js';
import iconLoader from '@carbon/web-components/es/globals/internal/icon-loader.js';
import UsersIcon from '@carbon/icons/es/user--multiple/32.js';

///////////////////////////////////////////////////////////////////////////////
// PARTS

// AddButton is the icon of a button which adds
const AddButton = iconLoader(AddIcon, { slot: 'icon' });

// userColumns are the columns of a table of users: the name, full name,
// mail address, and user ID, of a posixAccount
export const userColumns: Column<LdapObject>[] = [
    { header: 'Name', cell: (user) => html`<code style="font-family: 'IBM Plex Mono', monospace; font-size: 0.875rem">${rdnValue(user.dn)}</code>` },
    { header: 'Full name', cell: (user) => first(user, 'cn') ?? '' },
    { header: 'Mail', cell: (user) => first(user, 'mail') ?? '' },
    { header: 'UID', cell: (user) => first(user, 'uidNumber') ?? '' },
];

// passwordFormView is the form which sets a password, which is generated,
// or else typed twice. rerender is called when the checkbox changes which
// inputs it shows.
export function passwordFormView(form: PasswordForm, rerender: () => void, errors: PasswordFormErrors = {}): TemplateResult {
    return html`
        <div class="form">
            <cds-checkbox .checked=${form.generate} @cds-checkbox-changed=${(event: Event) => {
                form.generate = (event.target as HTMLInputElement).checked;
                rerender();
            }}>Generate a password</cds-checkbox>
            ${form.generate ? html`<p class="helper">The directory generates one, which is shown once.</p>` : html`
                <cds-password-input label="Password" .value=${live(form.password)} autocomplete="new-password"
                    ?invalid=${!!errors.password} invalid-text=${errors.password ?? ''}
                    @input=${(event: Event) => { form.password = (event.target as HTMLInputElement).value; }}></cds-password-input>
                <cds-password-input label="Password again" .value=${live(form.confirm)} autocomplete="new-password"
                    ?invalid=${!!errors.confirm} invalid-text=${errors.confirm ?? ''}
                    @input=${(event: Event) => { form.confirm = (event.target as HTMLInputElement).value; }}></cds-password-input>
            `}
        </div>
    `;
}

///////////////////////////////////////////////////////////////////////////////
// PAGE

export const LdapUsersTag = 'ga-ldap-users';

// Body is what the panel shows, and its kind, which says whether a form is
// open, so the panel isn't closed, or changed, when the list is loaded again
interface Body {
    kind: 'user' | 'form' | 'group' | 'password' | 'generated';
    content: TemplateResult;
    // dn is the user's, when it's one's
    dn?: string;
}

export class LdapUsersElement extends LdapPage {
    static override properties = {
        ...LdapPage.properties,
        controller: { attribute: false },
        heading: { type: String },
        body: { state: true },
    };

    // controller keeps the users, which is made with the client, when it
    // isn't given
    declare controller?: UserController;
    declare heading: string;
    declare private body?: Body;

    private readonly panel = new PanelController<Body>();
    private unsubscribe?: () => void;

    // schema is the users' object classes and attributes, which the form is
    // made from, loaded when it's first shown
    private schemas?: Promise<EntrySchemas>;

    // opened counts what's opened in the panel, so a response which arrives
    // after what it was for was closed, or another opened, is ignored
    private opened = 0;

    constructor() {
        super();
        this.heading = 'Users';
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
            this.controller = new UserController(this.client, { notifications: this.notifications, changes: this.changes });
        }
        if (changed.has('controller') || changed.has('client')) {
            this.watch();
        }
    }

    protected override render() {
        if (!this.controller) {
            return nothing;
        }
        const tools: TableToolbarAction[] = [{ label: 'Create a user', icon: AddIcon, run: () => this.edit() }];
        return html`
            <gs-page-header heading=${this.heading} .icon=${UsersIcon} .details=${this.details}></gs-page-header>
            <gs-table .controller=${this.controller.list} .columns=${userColumns} .itemKey=${(user: LdapObject) => user.dn.toLowerCase()}
                search="Search users" .toolbarActions=${tools}
                @gs-table-search=${(event: CustomEvent<TableSearch>) => { void this.controller?.setSearch(event.detail.value).then(() => this.requestUpdate()); }}
                @gs-table-action-error=${(event: CustomEvent<TableActionError<LdapObject>>) => this.notifications?.error(`${event.detail.action.label} didn't work`, event.detail.error)}
                empty=${this.controller.search ? 'No users match' : 'No users'}></gs-table>
            <gs-panel .controller=${this.panel}>${this.body?.content ?? nothing}</gs-panel>
        `;
    }

    // watch opens a user in the panel when it's opened in the table, and
    // closes the panel when it's closed, unless a form is open
    private watch() {
        this.unsubscribe?.();
        this.unsubscribe = this.isConnected ? this.controller?.list.subscribe(({ selected }) => {
            if (selected) {
                if (!this.panel.isOpen || !this.body?.dn || !sameDN(this.body.dn, selected.dn) || this.body.kind === 'user') {
                    this.show(selected);
                }
            } else if (this.panel.isOpen && this.body?.kind === 'user') {
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

    // show shows a user's groups and attributes, and what can be done with it
    private show(user: LdapObject) {
        const name = rdnValue(user.dn);
        this.open(name, first(user, 'cn') ?? 'User', {
            kind: 'user',
            dn: user.dn,
            content: html`${this.groupsView(user)}${attrsView(user)}`,
        }, [
            { label: 'Delete', kind: 'danger', close: false, run: () => this.delete(user) },
            { label: 'Edit', kind: 'secondary', close: false, run: () => this.edit(user) },
            { label: 'Set password', kind: 'primary', close: false, run: () => this.password(user) },
        ]);
    }

    // groupsView is the groups the user is in, each of which it's removed
    // from when its tag is closed
    private groupsView(user: LdapObject): unknown {
        // Without groups, which the manager can be without, there are none
        const client = this.client;
        if (!client || !this.current?.group_dn) {
            return nothing;
        }
        const name = rdnValue(user.dn);
        const groups = listAllGroups(client, { user: name, attr: ['cn'] });
        return until(groups.then((found) => html`
            <p class="helper">${found.length ? 'Groups' : 'It isn\'t in any groups'}</p>
            <div style="display: flex; flex-wrap: wrap; align-items: center; gap: 0.25rem; margin-bottom: 1rem">
                ${found.map((group) => {
                    const cn = rdnValue(group.dn);
                    return html`<cds-dismissible-tag size="sm" text=${cn} tag-title=${`Remove ${name} from ${cn}`}
                        @cds-dismissible-tag-beingclosed=${(event: Event) => {
                            event.preventDefault();
                            void this.removeFromGroup(user, cn);
                        }}></cds-dismissible-tag>`;
                })}
                <cds-button kind="ghost" size="sm" @click=${() => this.addToGroup(user)}>Add to a group${AddButton}</cds-button>
            </div>
        `, (error: unknown) => {
            this.notifications?.error(`${name}'s groups couldn't be loaded`, error);
            return nothing;
        }), nothing);
    }

    // edit shows the form which creates a user, or edits one, from the
    // users' object classes, once they're loaded, and shows it
    private async edit(user?: LdapObject) {
        if (!this.client) {
            return;
        }

        // A new user isn't the one selected, which the list would show again
        // in place of the form, when it's loaded again
        if (!user) {
            this.controller?.list.close();
        }

        // A new user's form is of the classes users are created with, and an
        // existing one's of its own classes
        const opened = this.opened;
        this.schemas ??= loadEntrySchemas(this.client, 'user');
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

        const form = entryForm(user ? schemas.of(user) : schemas.created, user);
        let errors: EntryFormErrors = {};
        const rerender = () => {
            this.body = { kind: 'form', dn: user?.dn, content: entryFormView(form, rerender, errors) };
        };
        const cancel: PanelAction = user
            ? { label: 'Cancel', kind: 'secondary', close: false, run: () => this.show(user) }
            : { label: 'Cancel', kind: 'secondary' };
        this.open(user ? `Edit ${rdnValue(user.dn)}` : 'Create a user', 'User', {
            kind: 'form',
            dn: user?.dn,
            content: entryFormView(form, rerender, errors),
        }, [cancel, {
            label: user ? 'Save' : 'Create',
            kind: 'primary',
            close: false,
            run: async () => {
                errors = entryFormErrors(form);
                rerender();
                if (Object.keys(errors).length || !this.client) {
                    return;
                }
                const attrs = entryAttrs(form);
                if (!user) {
                    const created = await api.createUser(this.client, form.name.trim(), attrs, form.allocateGID);
                    this.notifications?.push({ kind: 'success', title: `${rdnValue(created.dn)} was created` });
                    this.select(created);
                } else if (Object.keys(attrs).length) {
                    const updated = await api.updateUser(this.client, rdnValue(user.dn), attrs);
                    this.notifications?.push({ kind: 'success', title: `${rdnValue(updated.dn)} was changed` });
                    this.select(updated);
                } else {
                    this.notifications?.push({ kind: 'info', title: 'Nothing was changed' });
                    this.show(user);
                }
            },
        }]);
    }

    // select opens the user in the list, which shows it, so the list's
    // selection is the user the panel shows, such as a new, or renamed, one
    private select(user: LdapObject) {
        this.controller?.list.open(user);
        // The list shows it, unless it was already selected
        if (this.body?.kind !== 'user' || !this.body.dn || !sameDN(this.body.dn, user.dn)) {
            this.show(user);
        }
    }

    // addToGroup shows the groups the user can be added to, and adds it to
    // the one chosen
    private addToGroup(user: LdapObject) {
        const client = this.client;
        if (!client) {
            return;
        }
        const name = rdnValue(user.dn);
        const state = { group: '' };
        const choices = Promise.all([
            listAllGroups(client, { attr: ['cn'] }),
            listAllGroups(client, { user: name, attr: ['cn'] }),
        ]).then(([all, member]) => {
            const names = member.map((group) => group.dn);
            return all.filter((group) => !names.some((dn) => sameDN(dn, group.dn))).map((group) => rdnValue(group.dn));
        });
        const view = (error?: string) => html`
            <div class="form">
                ${until(choices.then((groups) => groups.length ? html`
                    <cds-combo-box title-text="Group" helper-text="Type to filter the groups" ?invalid=${!!error} invalid-text=${error ?? ''}
                        @cds-combo-box-selected=${(event: Event) => { state.group = (event.target as HTMLInputElement).value ?? ''; }}>
                        ${groups.map((group) => html`<cds-combo-box-item value=${group}>${group}</cds-combo-box-item>`)}
                    </cds-combo-box>
                ` : html`<p class="helper">It's in every group.</p>`, (err: unknown) => {
                    this.notifications?.error("The groups couldn't be loaded", err);
                    return nothing;
                }), nothing)}
            </div>
        `;
        this.open(`Add ${name} to a group`, 'User', { kind: 'group', dn: user.dn, content: view() }, [
            { label: 'Cancel', kind: 'secondary', close: false, run: () => this.show(user) },
            {
                label: 'Add',
                kind: 'primary',
                close: false,
                run: async () => {
                    if (!state.group) {
                        this.body = { kind: 'group', dn: user.dn, content: view('Choose a group') };
                        return;
                    }
                    await api.addGroupUsers(client, state.group, [name]);
                    this.notifications?.push({ kind: 'success', title: `${name} was added to ${state.group}` });
                    this.show(user);
                },
            },
        ]);
    }

    // removeFromGroup removes the user from the group, and shows it again,
    // when it's still shown
    private async removeFromGroup(user: LdapObject, group: string) {
        const name = rdnValue(user.dn);
        if (!this.client || !confirm(`Remove ${name} from ${group}?`)) {
            return;
        }
        const opened = this.opened;
        try {
            await api.removeGroupUsers(this.client, group, [name]);
        } catch (error) {
            this.notifications?.error(`${name} couldn't be removed from ${group}`, error);
            return;
        }
        this.notifications?.push({ kind: 'success', title: `${name} was removed from ${group}` });
        if (this.opened === opened && this.panel.isOpen) {
            this.show(user);
        }
    }

    // password sets the user's password, as the manager, to one typed, or
    // generated, which is shown once
    private password(user: LdapObject) {
        const name = rdnValue(user.dn);
        const form = passwordForm();
        let errors: PasswordFormErrors = {};
        const rerender = () => {
            this.body = { kind: 'password', dn: user.dn, content: passwordFormView(form, rerender, errors) };
        };
        this.open(`${name}'s password`, 'User', { kind: 'password', dn: user.dn, content: passwordFormView(form, rerender, errors) }, [
            { label: 'Cancel', kind: 'secondary', close: false, run: () => this.show(user) },
            {
                label: 'Set password',
                kind: 'primary',
                close: false,
                run: async () => {
                    errors = passwordFormErrors(form);
                    rerender();
                    if (Object.keys(errors).length || !this.client) {
                        return;
                    }

                    // A generated password is only shown when this form is
                    // still open, so it isn't revealed after the panel was
                    // closed, or something else opened
                    const opened = this.opened;
                    const result = await api.changePassword(this.client, user.dn, passwordRequest(form));
                    form.password = form.confirm = '';
                    this.notifications?.push({ kind: 'success', title: `${name}'s password was set` });
                    const generated = result['generated-password'];
                    if (this.opened !== opened || !this.panel.isOpen) {
                        return;
                    } else if (!generated) {
                        this.show(user);
                        return;
                    }
                    this.open(`${name}'s password`, 'User', {
                        kind: 'generated',
                        dn: user.dn,
                        content: secretView(generated, "The generated password, which isn't shown again"),
                    }, [{ label: 'Done', kind: 'primary', close: false, run: () => this.show(user) }]);
                },
            },
        ]);
    }

    // delete deletes a user, once it's confirmed
    private async delete(user: LdapObject) {
        const name = rdnValue(user.dn);
        if (!this.client || !confirm(`Delete ${name}? It can no longer sign in.`)) {
            return;
        }
        await api.deleteUser(this.client, name);
        this.notifications?.push({ kind: 'success', title: `${name} was deleted` });
        this.panel.close();
    }
}

if (!customElements.get(LdapUsersTag)) {
    customElements.define(LdapUsersTag, LdapUsersElement);
}

declare global {
    interface HTMLElementTagNameMap {
        [LdapUsersTag]: LdapUsersElement;
    }
}
