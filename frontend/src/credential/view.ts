// go-auth's credentials, as Lit elements, of Carbon's web components, which
// an app includes:
//
// - ga-credentials is a Credentials page: its header, which stores a
//   credential, the table of the credentials, and a panel, which opens one,
//   gets its value with its passphrase, replaces it, rotates it, and deletes
//   it. It's given the API's client, and the app's notifications.
// - credentialModule adds it to an app as a module, which owns the
//   Credentials item in the app's menu bar, and its sidebar while it's
//   active.
// - credentialColumns, credentialFormView and valueView are its parts, for
//   an app which shows credentials in its own table and panel.
//
// They need lit, @carbon/web-components and @mutablelogic/go-server, which
// are the package's peer dependencies.

import { LitElement, html, nothing, type PropertyValues, type TemplateResult } from 'lit';
import { ApiError, type Client } from '@mutablelogic/go-server/api';
import type { ChangesController } from '@mutablelogic/go-server/broadcaster';
import type { Column } from '@mutablelogic/go-server/list/view';
import type { NavController } from '@mutablelogic/go-server/nav';
import type { NotificationController } from '@mutablelogic/go-server/notification';
import { PanelController, type PanelAction } from '@mutablelogic/go-server/panel';
import type { PageAction } from '@mutablelogic/go-server/page';
import type { Router } from '@mutablelogic/go-server/router';
import { CredentialController } from './controller.ts';
import { credentialChange, credentialForm, credentialFormErrors, credentialRequest, type CredentialForm, type CredentialFormErrors } from './form.ts';
import { refreshable, type Credential, type CredentialFeatures } from './schema.ts';

// go-server's and Carbon's elements
import '@mutablelogic/go-server/list/view';
import '@mutablelogic/go-server/page/view';
import '@mutablelogic/go-server/panel/view';
import '@carbon/web-components/es/components/checkbox/index.js';
import '@carbon/web-components/es/components/copy-button/index.js';
import '@carbon/web-components/es/components/password-input/index.js';
import '@carbon/web-components/es/components/tag/index.js';
import '@carbon/web-components/es/components/text-input/index.js';
import '@carbon/web-components/es/components/textarea/index.js';
import AddIcon from '@carbon/icons/es/add/16.js';
import RenewIcon from '@carbon/icons/es/renew/16.js';
import PasswordIcon from '@carbon/icons/es/password/32.js';

///////////////////////////////////////////////////////////////////////////////
// PARTS

// credentialColumns are the columns of a table of credentials: the key,
// which can be copied, without opening the credential, its description, and
// when it was last changed, which sort it
export const credentialColumns: Column<Credential>[] = [
    { header: 'Key', cell: (credential) => keyView(credential.key, credential.rotate), sort: 'key', sortFirst: 'ascending' },
    { header: 'Description', cell: (credential) => credential.description ?? '' },
    { header: 'Updated', cell: (credential) => formatTime(credential.updated_at), sort: 'updated_at' },
];

// keyView is a credential's key, in a monospace font, with a button which
// copies it, and a tag when it needs rotating. A click on the button doesn't reach the table's row, so it
// doesn't open the credential.
export function keyView(key: string, rotate = false): TemplateResult {
    return html`
        <span class="ga-key" style="display: inline-flex; align-items: center; gap: 0.25rem">
            <code style="font-family: 'IBM Plex Mono', monospace; font-size: 0.875rem">${key}</code>
            <cds-copy-button size="sm" feedback="Copied" @click=${(event: Event) => {
                event.stopPropagation();
                void copyText(key);
            }}>Copy ${key}</cds-copy-button>
            ${rotate ? html`<cds-tag type="warm-gray" size="sm" title="It's encrypted with an older passphrase than the latest">Needs rotation</cds-tag>` : nothing}
        </span>
    `;
}

// credentialFormView is the form which stores a credential, or edits one:
// its key, which is fixed when it edits one, its description, and its
// value, as a password, which is typed again, or, when it's JSON, in a text
// area, once. When it edits one, an empty value keeps it. rerender is called
// when the JSON checkbox changes which inputs it shows.
export function credentialFormView(form: CredentialForm, rerender: () => void, errors: CredentialFormErrors = {}): TemplateResult {
    return html`
        <div class="form">
            <cds-text-input label="Key" value=${form.key} ?readonly=${form.replace}
                helper-text=${form.replace ? 'The credential which is changed' : 'A letter, then letters, digits, _ and -, such as OPENAI_API_KEY'}
                ?invalid=${!!errors.key} invalid-text=${errors.key ?? ''}
                @input=${(event: Event) => { form.key = (event.target as HTMLInputElement).value; }}></cds-text-input>
            <cds-text-input label="Description" value=${form.description}
                helper-text="What it's for, which isn't secret, so it's shown in the list"
                @input=${(event: Event) => { form.description = (event.target as HTMLInputElement).value; }}></cds-text-input>
            ${form.json ? html`
                <cds-textarea label="Value" rows="6" value=${form.value}
                    helper-text=${form.replace ? 'Leave it empty to keep the value' : 'Any JSON, such as an object with a user and a password'}
                    ?invalid=${!!errors.value} invalid-text=${errors.value ?? ''}
                    @input=${(event: Event) => { form.value = (event.target as HTMLTextAreaElement).value; }}></cds-textarea>
            ` : html`
                <cds-password-input label="Value" value=${form.value} autocomplete="off"
                    helper-text=${form.replace ? 'Leave it empty to keep the value' : 'Stored encrypted, and never shown without its passphrase'}
                    ?invalid=${!!errors.value} invalid-text=${errors.value ?? ''}
                    @input=${(event: Event) => { form.value = (event.target as HTMLInputElement).value; }}></cds-password-input>
                <cds-password-input label="Value again" value=${form.confirm} autocomplete="off"
                    helper-text="The same value, to be sure it's right"
                    ?invalid=${!!errors.confirm} invalid-text=${errors.confirm ?? ''}
                    @input=${(event: Event) => { form.confirm = (event.target as HTMLInputElement).value; }}></cds-password-input>
            `}
            <cds-checkbox .checked=${form.json} @cds-checkbox-changed=${(event: Event) => {
                form.json = (event.target as HTMLInputElement).checked;
                form.confirm = '';
                rerender();
            }}>The value is JSON</cds-checkbox>
        </div>
    `;
}

// passphraseFormView asks for the passphrase a credential was encrypted
// with, which its value is shown with
export function passphraseFormView(state: { passphrase: string }, error?: string): TemplateResult {
    return html`
        <div class="form">
            <cds-password-input label="Passphrase" value=${state.passphrase} autocomplete="off"
                helper-text="The passphrase the credential was encrypted with"
                ?invalid=${!!error} invalid-text=${error ?? ''}
                @input=${(event: Event) => { state.passphrase = (event.target as HTMLInputElement).value; }}></cds-password-input>
        </div>
    `;
}

// valueView shows a credential's value: text as it is, and any other JSON
// indented
export function valueView(value: unknown): TemplateResult {
    return html`<pre class="value">${typeof value === 'string' ? value : JSON.stringify(value, null, 2)}</pre>`;
}

///////////////////////////////////////////////////////////////////////////////
// PAGE

// CredentialsTag is the page element's tag
export const CredentialsTag = 'ga-credentials';

// Body is what the panel shows, and its kind, which says whether a form, or
// a value, is open, so the panel isn't closed when the list's item is
interface Body {
    kind: 'credential' | 'form' | 'passphrase' | 'value';
    content: TemplateResult;
    // key is the credential's, when it's one's, so the panel isn't shown
    // again when the list is loaded again, with the same one selected
    key?: string;
}

export class CredentialsElement extends LitElement {
    static override properties = {
        client: { attribute: false },
        controller: { attribute: false },
        notifications: { attribute: false },
        changes: { attribute: false },
        features: { attribute: false },
        heading: { type: String },
        body: { state: true },
        rotations: { state: true },
    };

    // client is the credential API's client, which the controller is made
    // with, when it isn't given
    declare client?: Client;

    // controller keeps the credentials, which can be shared with other views
    declare controller?: CredentialController;

    // notifications show what's done, and errors, and changes load the
    // credentials again, when they change
    declare notifications?: NotificationController;
    declare changes?: ChangesController;

    // features are what the server's credential manager can do, from its
    // configuration, which hides what it can't, such as getting a value.
    // Everything is offered when they aren't known, such as from an older
    // server.
    declare features?: CredentialFeatures;

    // heading is the page's title
    declare heading: string;

    // body is what the panel shows
    declare private body?: Body;

    // rotations is how many credentials need rotating, which Rotate all
    // rotates
    declare private rotations: number;

    private readonly panel = new PanelController<Body>();

    // opened counts what's opened in the panel, so a response which arrives
    // after what it was for was closed, or another opened, is ignored
    private opened = 0;
    private unsubscribe?: () => void;

    constructor() {
        super();
        this.heading = 'Credentials';
        this.rotations = 0;
        this.panel.onClose(() => this.controller?.list.close());
        this.panel.onError((error, action) => this.notifications?.error(`${action.label} didn't work`, error));
    }

    // It renders without a shadow root, so the app's Carbon theme applies
    protected override createRenderRoot(): HTMLElement {
        return this;
    }

    override connectedCallback() {
        super.connectedCallback();
        this.watch();
    }

    override disconnectedCallback() {
        this.unsubscribe?.();
        this.unsubscribe = undefined;
        super.disconnectedCallback();
    }

    protected override willUpdate(changed: PropertyValues<this>) {
        if (!this.controller && this.client) {
            this.controller = new CredentialController(this.client, { notifications: this.notifications, changes: this.changes });
        }
        if (changed.has('controller') || changed.has('client')) {
            this.watch();
        }
    }

    protected override render() {
        if (!this.controller) {
            return nothing;
        }
        const actions: PageAction[] = [];
        if ((this.features?.rotate ?? true) && this.rotations > 0) {
            actions.push({ label: `Rotate all (${this.rotations})`, kind: 'secondary', run: () => this.rotateAll() });
        }
        if (refreshable(this.features?.backend)) {
            actions.push({ label: 'Refresh', kind: 'secondary', icon: RenewIcon, run: () => this.controller?.list.refresh() });
        }
        actions.push({ label: 'Store a credential', icon: AddIcon, run: () => this.store() });
        return html`
            <gs-page-header heading=${this.heading} subtitle="Secrets, such as API keys, which the server uses, stored encrypted"
                .icon=${PasswordIcon} .actions=${actions}></gs-page-header>
            <gs-table .controller=${this.controller.list} .columns=${credentialColumns}
                empty="No credentials are stored"></gs-table>
            <gs-panel .controller=${this.panel}>${this.body?.content ?? nothing}</gs-panel>
        `;
    }

    // watch opens a credential in the panel when it's opened in the table,
    // and closes the panel when it's closed, unless a form is open
    private watch() {
        this.unsubscribe?.();
        this.unsubscribe = this.isConnected ? this.controller?.list.subscribe(({ selected }) => {
            this.rotations = this.controller?.rotations ?? 0;
            if (selected) {
                // The list is loaded again, such as when a credential
                // changes, with the same one selected: its details are
                // shown again, but a form, or its value, is kept, with what
                // was typed in it
                if (!this.panel.isOpen || this.body?.key !== selected.key || this.body.kind === 'credential') {
                    this.show(selected);
                }
            } else if (this.panel.isOpen && this.body?.kind === 'credential') {
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

    // show shows a credential, and what can be done with it, which its
    // manager can do
    private show(credential: Credential) {
        const updated = credential.updated_at ? `Updated ${formatTime(credential.updated_at)}` : 'Credential';
        const decrypt = this.features?.decrypt ?? true;
        // Rotate is only offered when the credential needs it, and is then
        // the main action
        const rotate = (this.features?.rotate ?? true) && !!credential.rotate;
        const actions: PanelAction[] = [
            { label: 'Delete', kind: 'danger', close: false, run: () => this.delete(credential) },
            { label: 'Edit', kind: decrypt || rotate ? 'secondary' : 'primary', close: false, run: () => this.store(credential) },
        ];
        if (decrypt) {
            actions.push({ label: 'Get value', kind: rotate ? 'secondary' : 'primary', close: false, run: () => this.passphrase(credential) });
        }
        if (rotate) {
            actions.push({ label: 'Rotate', kind: 'primary', close: false, run: () => this.rotate(credential) });
        }
        this.open(credential.key, updated, {
            kind: 'credential',
            key: credential.key,
            content: html`${credential.description ? html`<p class="description">${credential.description}</p>` : nothing}${rotate
                ? html`<p class="helper">It's encrypted with an older passphrase than the latest, so it needs rotating.</p>`
                : nothing}<p class="helper">${decrypt
                ? 'Its value is only shown with the passphrase it was encrypted with.'
                : `Its value isn't shown, as it's stored in ${backendName(this.features?.backend)}.`}</p>`,
        }, actions);
    }

    // store shows the form which stores a new credential, or edits one,
    // which changes its value and description, or its description alone,
    // and shows it
    private store(credential?: Credential) {
        const form = credentialForm(credential);
        let errors: CredentialFormErrors = {};
        const rerender = () => {
            this.body = { kind: 'form', key: credential?.key, content: credentialFormView(form, rerender, errors) };
        };
        const cancel: PanelAction = credential
            ? { label: 'Cancel', kind: 'secondary', close: false, run: () => this.show(credential) }
            : { label: 'Cancel', kind: 'secondary' };
        this.open(credential ? `Edit ${credential.key}` : 'Store a credential', 'Credential', {
            kind: 'form',
            key: credential?.key,
            content: credentialFormView(form, rerender, errors),
        }, [cancel, {
            label: credential ? 'Save' : 'Store',
            kind: 'primary',
            close: false,
            run: async () => {
                errors = credentialFormErrors(form);
                rerender();
                if (Object.keys(errors).length || !this.controller) {
                    return;
                }
                switch (credentialChange(form)) {
                    case 'value': {
                        const stored = await this.controller.set(credentialRequest(form));
                        this.notifications?.push({ kind: 'success', title: credential ? `${stored.key} was changed` : `${stored.key} was stored` });
                        this.show({ key: stored.key, description: form.description.trim() || undefined, updated_at: stored.updated_at ?? credential?.updated_at });
                        break;
                    }
                    case 'description': {
                        const described = await this.controller.describe(form.key.trim(), form.description);
                        this.notifications?.push({ kind: 'success', title: `${described.key}'s description was changed` });
                        this.show({ key: described.key, description: described.description || undefined, updated_at: credential?.updated_at });
                        break;
                    }
                    default:
                        this.notifications?.push({ kind: 'info', title: 'Nothing was changed' });
                        if (credential) {
                            this.show(credential);
                        }
                }
            },
        }]);
    }

    // passphrase asks for a credential's passphrase, and shows its value
    private passphrase(credential: Credential) {
        const state = { passphrase: '' };
        this.open(`${credential.key}'s value`, 'Credential', {
            kind: 'passphrase',
            key: credential.key,
            content: passphraseFormView(state),
        }, [
            { label: 'Cancel', kind: 'secondary', close: false, run: () => this.show(credential) },
            {
                label: 'Show',
                kind: 'primary',
                close: false,
                run: async () => {
                    if (!state.passphrase || !this.controller) {
                        this.body = { kind: 'passphrase', key: credential.key, content: passphraseFormView(state, 'A passphrase is required') };
                        return;
                    }

                    // The value is only shown when this form is still open,
                    // so it isn't revealed after the panel was closed, or
                    // something else was opened, while it was being read
                    const opened = this.opened;
                    const current = () => this.opened === opened && this.panel.isOpen && this.isConnected;

                    // A wrong passphrase is said beside it, rather than as an
                    // error which goes away
                    let value: unknown;
                    try {
                        value = await this.controller.value(credential.key, state.passphrase);
                    } catch (error) {
                        if (!current()) {
                            return;
                        } else if (error instanceof ApiError && error.status === 403) {
                            this.body = { kind: 'passphrase', key: credential.key, content: passphraseFormView(state, "It isn't the passphrase the credential was encrypted with") };
                            return;
                        }
                        throw error;
                    }
                    state.passphrase = '';
                    if (!current()) {
                        return;
                    }
                    this.open(`${credential.key}'s value`, 'Credential', { kind: 'value', key: credential.key, content: valueView(value) }, [
                        { label: 'Hide', kind: 'secondary', close: false, run: () => this.show(credential) },
                    ]);
                },
            },
        ]);
    }

    // rotate re-encrypts a credential with the latest passphrase version,
    // and shows it, without Rotate
    private async rotate(credential: Credential) {
        if (!this.controller) {
            return;
        }
        const rotated = await this.controller.rotate(credential.key);
        this.notifications?.push(rotated
            ? { kind: 'success', title: `${credential.key} was re-encrypted with the latest passphrase` }
            : { kind: 'info', title: `${credential.key} already uses the latest passphrase` });
        if (this.panel.isOpen && this.body?.key === credential.key) {
            this.show({ ...credential, rotate: false });
        }
    }

    // rotateAll re-encrypts each credential which needs it with the latest
    // passphrase version
    private async rotateAll() {
        if (!this.controller) {
            return;
        }
        const rotated = await this.controller.rotateAll();
        this.rotations = this.controller.rotations;
        this.notifications?.push({ kind: 'success', title: rotated === 1 ? '1 credential was rotated' : `${rotated} credentials were rotated` });
    }

    // delete deletes a credential, once it's confirmed
    private async delete(credential: Credential) {
        if (!this.controller || !confirm(`Delete ${credential.key}? Anything which uses it can no longer authenticate.`)) {
            return;
        }
        await this.controller.delete(credential.key);
        this.notifications?.push({ kind: 'success', title: `${credential.key} was deleted` });
        this.panel.close();
    }
}

if (!customElements.get(CredentialsTag)) {
    customElements.define(CredentialsTag, CredentialsElement);
}

declare global {
    interface HTMLElementTagNameMap {
        [CredentialsTag]: CredentialsElement;
    }
}

///////////////////////////////////////////////////////////////////////////////
// MODULE

// CredentialApp is what the module needs of the app which includes it: its
// navigation, its router, the credential API's client, its notifications
// and changes, and the element its pages are added to
export interface CredentialApp {
    nav: NavController;
    router: Router;
    client: Client;
    root: HTMLElement;
    notifications?: NotificationController;
    changes?: ChangesController;
    // features are what the server's credential manager can do, such as
    // from configSection(config, 'credential')
    features?: CredentialFeatures;
}

// credentialModule adds the Credentials module to the app: its section,
// which owns the menu bar's Credentials item, and the sidebar while it's
// active, of its page, which it adds to the root, and routes to. The page's
// id is page-credentials, not the hash it's routed to, so the browser
// doesn't scroll to it.
export function credentialModule(app: CredentialApp, section = 'Credentials'): CredentialsElement {
    const page = document.createElement('section');
    page.id = 'page-credentials';
    page.className = 'page';
    page.hidden = true;

    const element = document.createElement(CredentialsTag);
    element.client = app.client;
    element.notifications = app.notifications;
    element.changes = app.changes;
    element.features = app.features;
    page.append(element);
    app.root.append(page);

    app.nav.setSection(section, [{ id: 'credentials', label: 'Credentials', href: '#credentials' }]);
    app.router.add('credentials', page);
    return element;
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// backendName returns the name of a backend, to say where values are
function backendName(backend?: string): string {
    switch (backend) {
        case 'aws':
            return 'AWS Secrets Manager';
        case 'bitwarden':
            return 'Bitwarden Secrets Manager';
        default:
            return backend ? `the ${backend} backend` : 'the backend';
    }
}

// copyText copies the text to the clipboard, which needs a secure page, or
// else selects it in a text area, and copies the selection
async function copyText(text: string): Promise<void> {
    if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return;
    }
    const area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.append(area);
    area.select();
    document.execCommand('copy');
    area.remove();
}

// formatTime returns a time in the user's locale, or nothing
function formatTime(value?: string): string {
    if (!value) {
        return '';
    }
    const time = new Date(value);
    return Number.isNaN(time.getTime()) ? value : time.toLocaleString();
}
