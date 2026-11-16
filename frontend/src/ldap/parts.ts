// The LDAP pages' parts: the base of a page, which follows the directory's
// status, and shows it in its header, an entry's attributes, and a value
// which is copied

import { LitElement, html, nothing, type TemplateResult } from 'lit';
import type { Client } from '@mutablelogic/go-server/api';
import type { ChangesController } from '@mutablelogic/go-server/broadcaster';
import type { NotificationController } from '@mutablelogic/go-server/notification';
import type { LdapStatusController } from './controller.ts';
import { live } from 'lit/directives/live.js';
import { addable, attrLabel, defaultValue, formFields, isPosix, isRequired, namingAttr, type EntryForm, type EntryFormErrors } from './form.ts';
import { valueText, type LdapObject, type LdapStatus } from './schema.ts';

// Carbon components
import '@carbon/web-components/es/components/checkbox/index.js';
import '@carbon/web-components/es/components/combo-box/index.js';
import '@carbon/web-components/es/components/copy-button/index.js';
import '@carbon/web-components/es/components/password-input/index.js';
import '@carbon/web-components/es/components/text-input/index.js';
import '@carbon/web-components/es/components/tag/index.js';

///////////////////////////////////////////////////////////////////////////////
// PAGE

// LdapPage is the base of the module's pages: the API's client, the app's
// notifications and changes, and the directory's status, which it follows,
// for its header. It renders without a shadow root, so the app's Carbon
// theme applies, such as to the header's.
export class LdapPage extends LitElement {
    static override properties = {
        client: { attribute: false },
        status: { attribute: false },
        notifications: { attribute: false },
        changes: { attribute: false },
        current: { state: true },
    };

    declare client?: Client;
    declare status?: LdapStatusController;
    declare notifications?: NotificationController;
    declare changes?: ChangesController;

    // current is the directory's status, as it is now
    declare protected current?: LdapStatus;
    private unsubscribeStatus?: () => void;

    protected override createRenderRoot(): HTMLElement {
        return this;
    }

    override connectedCallback(): void {
        super.connectedCallback();
        this.unsubscribeStatus = this.status?.subscribe((status) => {
            this.current = status;
        });
    }

    override disconnectedCallback(): void {
        this.unsubscribeStatus?.();
        this.unsubscribeStatus = undefined;
        super.disconnectedCallback();
    }

    // details is the header's details: the directory's status
    protected get details(): unknown {
        return this.current ? statusView(this.current) : nothing;
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
// ATTRIBUTES

// attrsView is an entry's DN and attributes, by name, in a list of terms,
// each with its values, one beneath another, and a value which isn't UTF-8
// as its size. Its object classes are first.
export function attrsView(object: LdapObject): TemplateResult {
    const names = Object.keys(object.attrs ?? {}).sort((a, b) => {
        const ac = a.toLowerCase() === 'objectclass', bc = b.toLowerCase() === 'objectclass';
        return ac === bc ? a.localeCompare(b) : ac ? -1 : 1;
    });
    return html`
        <dl class="details">
            <dt>DN</dt>
            <dd><code style="font-family: 'IBM Plex Mono', monospace">${object.dn}</code></dd>
            ${names.map((name) => html`
                <dt>${name}</dt>
                <dd>${(object.attrs?.[name] ?? []).map((value, i) => html`${i ? html`<br>` : nothing}${valueText(value)}`)}</dd>
            `)}
        </dl>
    `;
}

// secretView is a value which is shown once, such as a generated password,
// with a button which copies it
export function secretView(value: string, note: string): TemplateResult {
    return html`
        <p class="helper">${note}</p>
        <div style="display: flex; align-items: center; gap: 0.25rem">
            <pre class="value" style="flex: 1">${value}</pre>
            <cds-copy-button feedback="Copied" @click=${() => void navigator.clipboard?.writeText(value)}>Copy</cds-copy-button>
        </div>
    `;
}

///////////////////////////////////////////////////////////////////////////////
// FORMS

// entryFormView is the form which creates an entry, such as a user, or
// edits one, from its object classes: its name, the attributes it must
// have, those which are common, and those which are added, and, for a new
// user, its password, typed twice, and whether its group ID is its user ID.
// rerender is called when what it shows changes.
export function entryFormView(form: EntryForm, rerender: () => void, errors: EntryFormErrors = {}): TemplateResult {
    const user = form.schema.kind === 'user';
    const more = addable(form);
    // An entry's name is the value of the attribute which names it, which
    // is said
    const naming = namingAttr(form.schema);
    const helper = form.original
        ? `Changing it renames the ${form.schema.kind}`
        : user ? 'What the user signs in with, such as alice'
            : form.schema.kind === 'group' ? 'Such as developers' : `Its ${naming}, which is in its DN, as ${naming}=…`;
    return html`
        <div class="form">
            <cds-text-input label=${form.schema.kind === 'entry' ? `Name (${naming})` : 'Name'} .value=${live(form.name)}
                helper-text=${helper}
                ?invalid=${!!errors.name} invalid-text=${errors.name ?? ''}
                @input=${(event: Event) => { form.name = (event.target as HTMLInputElement).value; }}></cds-text-input>
            ${isPosix(form.schema) && !form.original ? html`
                <cds-checkbox .checked=${form.allocateGID} @cds-checkbox-changed=${(event: Event) => {
                    form.allocateGID = (event.target as HTMLInputElement).checked;
                    rerender();
                }}>Its group ID is its user ID</cds-checkbox>
            ` : nothing}
            ${formFields(form).map((name) => attrInputView(form, name, errors[name]))}
            ${more.length ? html`
                <cds-combo-box title-text="Add an attribute" helper-text=${`One of the ${more.length} more which the ${form.schema.kind} can have`}
                    @cds-combo-box-selected=${(event: Event) => {
                        const name = (event.target as HTMLInputElement).value;
                        if (name && !form.added.includes(name)) {
                            form.added.push(name);
                            rerender();
                        }
                    }}>
                    ${more.map((name) => html`<cds-combo-box-item value=${name}>${name}</cds-combo-box-item>`)}
                </cds-combo-box>
            ` : nothing}
            ${user && !form.original ? html`
                <cds-password-input label="Password (optional)" .value=${live(form.password)} autocomplete="new-password"
                    helper-text="Leave it empty for a user without one, whose password can be set later"
                    @input=${(event: Event) => { form.password = (event.target as HTMLInputElement).value; }}></cds-password-input>
                <cds-password-input label="Password again" .value=${live(form.confirm)} autocomplete="new-password"
                    helper-text="The same password, to be sure it's right"
                    ?invalid=${!!errors.confirm} invalid-text=${errors.confirm ?? ''}
                    @input=${(event: Event) => { form.confirm = (event.target as HTMLInputElement).value; }}></cds-password-input>
            ` : nothing}
        </div>
    `;
}

// attrInputView is an attribute's input, labelled optional when it isn't
// required, with its default, or its description, as its help
function attrInputView(form: EntryForm, name: string, error?: string): TemplateResult {
    const label = attrLabel(name);
    const fallback = defaultValue(form, name) ?? (name.toLowerCase() === 'homedirectory' && !form.original ? '/home/ and the name' : undefined);
    const description = form.schema.types.get(name.toLowerCase())?.description;
    const helper = fallback
        ? `Leave it empty for ${fallback}`
        : label !== name ? name : description ?? '';
    return html`
        <cds-text-input label=${isRequired(form, name) ? label : `${label} (optional)`} .value=${live(form.values[name] ?? '')}
            helper-text=${helper} ?invalid=${!!error} invalid-text=${error ?? ''}
            @input=${(event: Event) => { form.values[name] = (event.target as HTMLInputElement).value; }}></cds-text-input>
    `;
}
