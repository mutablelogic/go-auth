// go-auth's certificates, as Lit elements, of Carbon's web components, which
// an app includes:
//
// - ga-certificates is a page of certificate authorities, or of leaf
//   certificates, by its kind: its header, which creates one, the table of
//   them, and a panel, which opens one, downloads it, with its chain, and a
//   leaf certificate's private key, renews it, enables or disables it, and
//   changes its tags. It's given the API's client, and the app's
//   notifications.
// - certModule adds a Certificate Authorities page, and a Leaf Certificates
//   page, to an app as a module, which owns the Certificates item in the
//   app's menu bar, and its sidebar, of the two pages, while it's active.
// - authorityColumns, certificateColumns, certFormView and certDetailsView
//   are its parts, for an app which shows certificates in its own table and
//   panel.
//
// They need lit, @carbon/web-components and @mutablelogic/go-server, which
// are the package's peer dependencies.

import { LitElement, html, nothing, type PropertyValues, type TemplateResult } from 'lit';
import { live } from 'lit/directives/live.js';
import { until } from 'lit/directives/until.js';
import type { Client } from '@mutablelogic/go-server/api';
import type { ChangesController } from '@mutablelogic/go-server/broadcaster';
import type { Column, TableSearch, TableSetting, TableSettingChange } from '@mutablelogic/go-server/list/view';
import type { NavController } from '@mutablelogic/go-server/nav';
import type { NotificationController } from '@mutablelogic/go-server/notification';
import { PanelController, type PanelAction } from '@mutablelogic/go-server/panel';
import type { PageAction } from '@mutablelogic/go-server/page';
import type { Router } from '@mutablelogic/go-server/router';
import { CertController } from './controller.ts';
import {
    certForm, certFormErrors, certRequest, renewForm, renewFormErrors, renewRequest, tagsError, tagsRequest,
    type CertForm, type CertFormErrors, type RenewForm,
} from './form.ts';
import { certificatePEM, download, privateKeyPEM } from './pem.ts';
import { copyText, formatTime, subjectView } from './parts.ts';
import { SubjectsElement, SubjectsTag } from './subject.ts';

export * from './subject.ts';
import { RootCertName, certExpired, certType, type CertFeatures, type Certificate, type Subject } from './schema.ts';

// go-server's and Carbon's elements
import '@mutablelogic/go-server/list/view';
import '@mutablelogic/go-server/page/view';
import '@mutablelogic/go-server/panel/view';
import '@carbon/web-components/es/components/button/index.js';
import '@carbon/web-components/es/components/copy-button/index.js';
import '@carbon/web-components/es/components/select/index.js';
import '@carbon/web-components/es/components/tag/index.js';
import '@carbon/web-components/es/components/text-input/index.js';
import '@carbon/web-components/es/components/textarea/index.js';
import iconLoader from '@carbon/web-components/es/globals/internal/icon-loader.js';
import AddIcon from '@carbon/icons/es/add/16.js';
import DownloadIcon from '@carbon/icons/es/download/16.js';
import CertificateIcon from '@carbon/icons/es/certificate/32.js';
import CertificateCheckIcon from '@carbon/icons/es/certificate--check/32.js';

///////////////////////////////////////////////////////////////////////////////
// PARTS

// DownloadButton is a download icon, in a button
const DownloadButton = iconLoader(DownloadIcon, { slot: 'icon' });

// authorityColumns are the columns of a table of certificate authorities,
// which the root signs: the name, which can be copied, without opening the
// certificate, when it expires, its state, and its tags
export const authorityColumns: Column<Certificate>[] = [
    { header: 'Name', cell: (cert) => nameView(cert.name) },
    { header: 'Expires', cell: (cert) => formatTime(cert.not_after) },
    { header: 'State', cell: (cert) => stateTags(cert) },
    { header: 'Tags', cell: (cert) => (cert.effective_tags ?? []).join(', ') },
];

// certificateColumns are the columns of a table of leaf certificates: the
// name, which can be copied, without opening the certificate, its SAN
// entries, the certificate authority which signed it, when it expires, its
// state, and its tags, with those it inherits
export const certificateColumns: Column<Certificate>[] = [
    { header: 'Name', cell: (cert) => nameView(cert.name) },
    { header: 'SAN', cell: (cert) => (cert.san ?? []).join(', ') },
    { header: 'Signer', cell: (cert) => signerName(cert) },
    { header: 'Expires', cell: (cert) => formatTime(cert.not_after) },
    { header: 'State', cell: (cert) => stateTags(cert) },
    { header: 'Tags', cell: (cert) => (cert.effective_tags ?? []).join(', ') },
];

// nameView is a certificate's name, in a monospace font, with a button which
// copies it. A click on the button doesn't reach the table's row, so it
// doesn't open the certificate.
export function nameView(name: string): TemplateResult {
    return html`
        <span style="display: inline-flex; align-items: center; gap: 0.25rem">
            <code style="font-family: 'IBM Plex Mono', monospace; font-size: 0.875rem">${name}</code>
            <cds-copy-button size="sm" feedback="Copied" @click=${(event: Event) => {
                event.stopPropagation();
                void copyText(name);
            }}>Copy ${name}</cds-copy-button>
        </span>
    `;
}

// certDetailsView shows a certificate: its subject, signer, SAN entries,
// validity and tags
export function certDetailsView(cert: Certificate): TemplateResult {
    const own = cert.tags ?? [];
    const inherited = (cert.effective_tags ?? []).filter((tag) => !own.includes(tag));
    const row = (term: string, value: unknown) => html`<dt>${term}</dt><dd>${value || '-'}</dd>`;
    return html`
        <div style="display: flex; gap: 0.5rem; margin-bottom: 1rem">${typeTag(cert)}${stateTags(cert)}</div>
        <dl class="details">
            ${row('Subject', cert.subject?.name)}
            ${row('Serial', html`<code>${cert.serial}</code>`)}
            ${row('Signer', signerName(cert))}
            ${cert.is_ca ? nothing : row('SAN', (cert.san ?? []).join(', '))}
            ${row('Valid from', formatTime(cert.not_before))}
            ${row('Valid until', formatTime(cert.not_after))}
            ${row('Tags', own.join(', '))}
            ${inherited.length ? row('Inherited tags', inherited.join(', ')) : nothing}
        </dl>
    `;
}

// certFormView is the form which creates a certificate authority, or a
// certificate, which a certificate authority of the list signs
export function certFormView(form: CertForm, authorities: readonly string[], errors: CertFormErrors = {}, subjects: readonly Subject[] = []): TemplateResult {
    return html`
        <div class="form">
            <cds-text-input label="Name" .value=${live(form.name)}
                helper-text=${form.ca ? 'Its common name: a letter, then letters, digits, _ and -' : 'Its common name, such as a host: a letter, then letters, digits, _ and -'}
                ?invalid=${!!errors.name} invalid-text=${errors.name ?? ''}
                @input=${(event: Event) => { form.name = (event.target as HTMLInputElement).value; }}></cds-text-input>
            ${form.ca ? nothing : html`
                <cds-select label-text="Certificate authority" .value=${live(form.signer)}
                    helper-text="Its latest version signs the certificate"
                    ?invalid=${!!errors.signer} invalid-text=${errors.signer ?? ''}
                    @cds-select-selected=${(event: CustomEvent<{ value: string }>) => { form.signer = event.detail?.value ?? form.signer; }}>
                    ${form.signer ? nothing : html`<cds-select-item value="">Choose one</cds-select-item>`}
                    ${authorities.map((name) => html`<cds-select-item value=${name} ?selected=${name === form.signer}>${name}</cds-select-item>`)}
                </cds-select>
                <cds-textarea label="SAN entries" rows="3" .value=${live(form.san)}
                    helper-text="DNS names, wildcards such as *.example.com, and IP addresses, separated by commas or lines"
                    ?invalid=${!!errors.san} invalid-text=${errors.san ?? ''}
                    @input=${(event: Event) => { form.san = (event.target as HTMLTextAreaElement).value; }}></cds-textarea>
            `}
            <cds-text-input label="Expiry, in days" .value=${live(form.expiry)}
                helper-text=${form.ca ? 'Five years when it\'s empty, and never after the root' : '90 days when it\'s empty, and never after its certificate authority'}
                ?invalid=${!!errors.expiry} invalid-text=${errors.expiry ?? ''}
                @input=${(event: Event) => { form.expiry = (event.target as HTMLInputElement).value; }}></cds-text-input>
            <cds-text-input label="Tags" .value=${live(form.tags)}
                helper-text="Separated by commas, which the certificates it signs inherit"
                ?invalid=${!!errors.tags} invalid-text=${errors.tags ?? ''}
                @input=${(event: Event) => { form.tags = (event.target as HTMLInputElement).value; }}></cds-text-input>
            <cds-select label-text="Subject" .value=${live(form.subjectId === undefined ? '' : String(form.subjectId))}
                helper-text=${form.ca ? 'Default is the root\'s subject. Subjects are created on the Subjects page.' : 'Default is its certificate authority\'s subject. Subjects are created on the Subjects page.'}
                @cds-select-selected=${(event: CustomEvent<{ value: string }>) => {
                    const value = event.detail?.value ?? '';
                    form.subjectId = value ? Number(value) : undefined;
                }}>
                <cds-select-item value="" ?selected=${form.subjectId === undefined}>Default</cds-select-item>
                ${subjects.map((subject) => html`<cds-select-item value=${String(subject.id)} ?selected=${subject.id === form.subjectId}>${subject.subject}</cds-select-item>`)}
            </cds-select>
        </div>
    `;
}

// renewFormView is the form which renews a certificate
export function renewFormView(form: RenewForm, cert: Certificate, errors: CertFormErrors = {}): TemplateResult {
    return html`
        <div class="form">
            <p class="helper">${cert.is_ca
                ? 'A new version is created, with the next serial, and this one stays enabled, so its certificates still work, until it\'s disabled or expires.'
                : 'A new version is created, with the next serial, signed by the latest version of its certificate authority, and this one is disabled.'}</p>
            <cds-text-input label="Expiry, in days" .value=${live(form.expiry)}
                helper-text="The current lifetime when it's empty, and never after its signer"
                ?invalid=${!!errors.expiry} invalid-text=${errors.expiry ?? ''}
                @input=${(event: Event) => { form.expiry = (event.target as HTMLInputElement).value; }}></cds-text-input>
            ${subjectView(form.subject, 'The fields which change, which are kept when they\'re empty')}
        </div>
    `;
}

///////////////////////////////////////////////////////////////////////////////
// PAGE

// CertificatesTag is the page element's tag
export const CertificatesTag = 'ga-certificates';

// Body is what the panel shows, and its kind, which says whether a form is
// open, so the panel isn't closed when the list's item is
interface Body {
    // version is an older version, which isn't the list's, so the list
    // doesn't replace it, or close the panel
    kind: 'certificate' | 'version' | 'form';
    content: TemplateResult;
    // key is the certificate's name and serial, when it's one's, so the
    // panel isn't shown again when the list is loaded again, with the same
    // one selected
    key?: string;
}

export class CertificatesElement extends LitElement {
    static override properties = {
        client: { attribute: false },
        controller: { attribute: false },
        notifications: { attribute: false },
        changes: { attribute: false },
        features: { attribute: false },
        kind: { type: String },
        heading: { type: String },
        createCertificate: { attribute: false },
        body: { state: true },
    };

    // client is the certificate API's client, which the controller is made
    // with, when it isn't given
    declare client?: Client;

    // controller keeps the certificates, which can be shared with other views
    declare controller?: CertController;

    // notifications show what's done, and errors, and changes load the
    // certificates again, when they change
    declare notifications?: NotificationController;
    declare changes?: ChangesController;

    // features are what the server's certificate manager can do, from its
    // configuration, such as whether a root is stored
    declare features?: CertFeatures;

    // kind is what the page has: certificate authorities, or leaf
    // certificates, which is set before it's connected
    declare kind: 'ca' | 'certificate';

    // heading is the page's title, which is the kind's when it's not set
    declare heading?: string;

    // createCertificate creates a leaf certificate, which a certificate
    // authority signs, when it's set, such as on another page of leaf
    // certificates. Otherwise it's created in this page's panel.
    declare createCertificate?: (signer: string) => void;

    // body is what the panel shows
    declare private body?: Body;

    private readonly panel = new PanelController<Body>();
    private unsubscribe?: () => void;

    // versions are the certificates' older versions, by their names, which
    // are loaded when their rows are expanded, until the list is loaded
    // again, and older are those versions' keys, which open as older
    // versions
    private readonly versions = new Map<string, Promise<Certificate[]>>();
    private readonly older = new Set<string>();
    private items?: readonly Certificate[];

    constructor() {
        super();
        this.kind = 'certificate';
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
            this.controller = new CertController(this.client, { notifications: this.notifications, changes: this.changes, ca: this.kind === 'ca' });
        }
        if (changed.has('controller') || changed.has('client')) {
            this.watch();
        }
    }

    protected override render() {
        if (!this.controller) {
            return nothing;
        }
        const root = this.features?.root ?? true;
        const authorities = this.kind === 'ca';
        const show = this.controller.showDisabled;
        const searching = !!this.controller.search;
        const actions: PageAction[] = [
            authorities
                ? { label: 'Create a certificate authority', icon: AddIcon, disabled: !root, run: () => this.create(true) }
                : { label: 'Create a certificate', icon: AddIcon, run: () => this.create(false) },
        ];
        const settings: TableSetting[] = [{ key: 'disabled', label: 'Show disabled', checked: show }];
        const empty = searching
            ? (authorities ? 'No certificate authorities match' : 'No leaf certificates match')
            : authorities
                ? (show ? 'No certificate authorities are stored' : 'No enabled certificate authorities')
                : (show ? 'No leaf certificates are stored' : 'No enabled leaf certificates');
        const subtitle = authorities
            ? (root ? 'Which the root signs, and which sign leaf certificates' : 'No root certificate is stored, so certificate authorities can\'t be created')
            : 'Such as a server\'s, which a certificate authority signs';
        return html`
            <gs-page-header heading=${this.heading ?? (authorities ? 'Certificate Authorities' : 'Leaf Certificates')}
                subtitle=${subtitle} .icon=${authorities ? CertificateCheckIcon : CertificateIcon} .actions=${actions}></gs-page-header>
            <gs-table .controller=${this.controller.list} .columns=${authorities ? authorityColumns : certificateColumns}
                .expand=${(cert: Certificate) => this.versionsView(cert)} .itemKey=${(cert: Certificate) => cert.name}
                .search=${authorities ? 'Search certificate authorities' : 'Search leaf certificates'} .settings=${settings}
                @gs-table-search=${(event: CustomEvent<TableSearch>) => { void this.controller?.setSearch(event.detail.value).then(() => this.requestUpdate()); }}
                @gs-table-setting=${(event: CustomEvent<TableSettingChange>) => {
                    if (event.detail.key === 'disabled') {
                        void this.toggleDisabled();
                    }
                }}
                empty=${empty}></gs-table>
            <gs-panel .controller=${this.panel}>${this.body?.content ?? nothing}</gs-panel>
        `;
    }

    // watch opens a certificate in the panel when it's opened in the table,
    // and closes the panel when it's closed, unless a form is open
    private watch() {
        this.unsubscribe?.();
        this.unsubscribe = this.isConnected ? this.controller?.list.subscribe(({ items, selected }) => {
            // The older versions are loaded again, when they're shown, once
            // the list is, as a certificate may have changed, or been renewed
            if (items !== this.items) {
                this.items = items;
                this.versions.clear();
            }
            if (selected) {
                if (!this.panel.isOpen || this.body?.key !== keyOf(selected) || this.body.kind === 'certificate') {
                    this.show(selected);
                }
            } else if (this.panel.isOpen && this.body?.kind === 'certificate') {
                this.panel.close();
            }
        }) : undefined;
    }

    // open shows the body in the panel, with its header and actions
    private open(title: string, subtitle: string, body: Body, actions: PanelAction[]) {
        this.body = body;
        this.panel.setHeader({ title, subtitle });
        this.panel.setActions(actions);
        this.panel.open(body);
    }

    // show shows a certificate, and what can be done with it. An older
    // version isn't renewed, and doesn't sign certificates.
    private show(cert: Certificate) {
        const ca = certType(cert) === 'ca';
        const enabled = cert.enabled ?? true;
        const older = this.older.has(keyOf(cert));
        const actions: PanelAction[] = [
            { label: enabled ? 'Disable' : 'Enable', kind: enabled ? 'danger' : 'secondary', close: false, run: () => this.enable(cert, !enabled) },
            { label: 'Tags', kind: older ? 'primary' : 'secondary', close: false, run: () => this.tags(cert) },
        ];
        if (enabled && !older) {
            actions.push({ label: 'Renew', kind: ca ? 'secondary' : 'primary', close: false, run: () => this.renew(cert) });
            if (ca) {
                actions.push({ label: 'Create a certificate', kind: 'primary', close: !!this.createCertificate, run: () => this.createCertificate ? this.createCertificate(cert.name) : this.create(false, cert.name) });
            }
        }
        // A certificate which is enabled is downloaded, with its chain, and a
        // leaf certificate's private key
        const downloads = enabled ? html`
            <div style="display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 1.5rem">
                <cds-button kind="tertiary" size="sm" @click=${() => this.download(cert)}>Download certificate${DownloadButton}</cds-button>
                ${ca ? nothing : html`<cds-button kind="tertiary" size="sm" @click=${() => this.downloadKey(cert)}>Download private key${DownloadButton}</cds-button>`}
            </div>
        ` : nothing;
        const note = older
            ? html`<p class="helper" style="margin-top: 1rem">An older version, which isn't renewed${ca ? ", and doesn't sign certificates" : ''}. Its latest version is in the list.</p>`
            : nothing;
        this.open(cert.name, older ? `${ca ? 'Certificate authority' : 'Certificate'}, an older version` : ca ? 'Certificate authority' : 'Certificate', {
            kind: older ? 'version' : 'certificate',
            key: keyOf(cert),
            content: html`${certDetailsView(cert)}${note}${downloads}`,
        }, actions);
    }

    // versionsView shows a certificate's older versions, beneath its row,
    // which are loaded once, until the list is loaded again, and opened in
    // the panel
    private versionsView(cert: Certificate): unknown {
        let versions = this.versions.get(cert.name);
        if (!versions) {
            versions = this.controller!.versions(cert.name).then((found) => {
                for (const version of found) {
                    this.older.add(keyOf(version));
                }
                return found;
            });
            this.versions.set(cert.name, versions);
        }
        return until(versions.then((found) => found.length ? html`
            <ul class="versions" style="list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.5rem">
                ${found.map((version) => html`
                    <li style="display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap">
                        <cds-button kind="ghost" size="sm" @click=${() => this.openVersion(version)}>Serial ${version.serial}</cds-button>
                        <span>Expires ${formatTime(version.not_after)}</span>
                        ${stateTags(version)}
                    </li>
                `)}
            </ul>
        ` : html`<p class="helper" style="margin: 0">No older versions</p>`, (error: unknown) => {
            this.notifications?.error(`${cert.name}'s older versions couldn't be loaded`, error);
            return nothing;
        }), html`<p class="helper" style="margin: 0">Loading older versions…</p>`);
    }

    // toggleDisabled shows disabled certificates, and their older versions,
    // which are disabled when a leaf certificate is renewed, or hides them
    private async toggleDisabled() {
        if (!this.controller) {
            return;
        }
        this.versions.clear();
        await this.controller.setShowDisabled(!this.controller.showDisabled);
        this.requestUpdate();
    }

    // openVersion opens an older version in the panel, rather than the list's
    // item, which is closed, so the list doesn't replace it
    private openVersion(version: Certificate) {
        this.older.add(keyOf(version));
        this.controller?.list.close();
        this.show(version);
    }

    // createLeaf shows the form which creates a leaf certificate, signed by
    // the certificate authority, when it's set
    createLeaf(signer?: string): Promise<void> {
        return this.create(false, signer);
    }

    // create shows the form which creates a certificate authority, or a
    // certificate, signed by the CA, when it's set
    private async create(ca: boolean, signer?: string) {
        if (!this.controller) {
            return;
        }
        const [authorities, subjects] = await Promise.all([ca ? [] : this.controller.authorities(), this.controller.subjects()]);
        if (!ca && !authorities.length) {
            this.notifications?.push({ kind: 'info', title: 'There\'s no enabled certificate authority to sign a certificate' });
            return;
        }
        const form = certForm(ca, signer ?? (authorities.length === 1 ? authorities[0] : ''));
        let errors: CertFormErrors = {};

        // The form has the selection's key, when a certificate is selected, so
        // the list being loaded again doesn't show the certificate in its place
        const selected = this.controller.list.current.selected;
        const key = selected ? keyOf(selected) : undefined;
        const rerender = () => {
            this.body = { kind: 'form', key, content: certFormView(form, authorities, errors, subjects) };
        };
        this.open(ca ? 'Create a certificate authority' : 'Create a certificate', ca ? 'Certificate authority' : 'Certificate', {
            kind: 'form',
            key,
            content: certFormView(form, authorities, errors, subjects),
        }, [{ label: 'Cancel', kind: 'secondary' }, {
            label: 'Create',
            kind: 'primary',
            close: false,
            run: async () => {
                errors = certFormErrors(form);
                rerender();
                if (Object.keys(errors).length || !this.controller) {
                    return;
                }
                const created = await this.controller.create(certRequest(form, subjects), ca ? undefined : form.signer);
                this.notifications?.push({ kind: 'success', title: `${created.name} was created` });
                this.select(created);
            },
        }]);
    }

    // renew shows the form which renews a certificate, and shows the new
    // version
    private renew(cert: Certificate) {
        const form = renewForm();
        let errors: CertFormErrors = {};
        this.open(`Renew ${cert.name}`, certType(cert) === 'ca' ? 'Certificate authority' : 'Certificate', {
            kind: 'form',
            key: keyOf(cert),
            content: renewFormView(form, cert, errors),
        }, [{ label: 'Cancel', kind: 'secondary', close: false, run: () => this.show(cert) }, {
            label: 'Renew',
            kind: 'primary',
            close: false,
            run: async () => {
                errors = renewFormErrors(form);
                this.body = { kind: 'form', key: keyOf(cert), content: renewFormView(form, cert, errors) };
                if (Object.keys(errors).length || !this.controller) {
                    return;
                }
                const renewed = await this.controller.renew(cert, renewRequest(form));
                this.notifications?.push({ kind: 'success', title: `${renewed.name} was renewed` });
                this.select(renewed);
            },
        }]);
    }

    // tags shows the form which changes a certificate's tags
    private tags(cert: Certificate) {
        const state = { tags: (cert.tags ?? []).join(', ') };
        const view = (error?: string) => html`
            <div class="form">
                <cds-text-input label="Tags" .value=${live(state.tags)}
                    helper-text="Separated by commas. The certificates it signs inherit them. None removes them."
                    ?invalid=${!!error} invalid-text=${error ?? ''}
                    @input=${(event: Event) => { state.tags = (event.target as HTMLInputElement).value; }}></cds-text-input>
            </div>
        `;
        this.open(`${cert.name}'s tags`, `Serial ${cert.serial}`, { kind: 'form', key: keyOf(cert), content: view() }, [
            { label: 'Cancel', kind: 'secondary', close: false, run: () => this.show(cert) },
            {
                label: 'Save',
                kind: 'primary',
                close: false,
                run: async () => {
                    const error = tagsError(state.tags);
                    if (error || !this.controller) {
                        this.body = { kind: 'form', key: keyOf(cert), content: view(error) };
                        return;
                    }
                    const updated = await this.controller.update(cert, tagsRequest(state.tags));
                    this.notifications?.push({ kind: 'success', title: `${updated.name}'s tags were changed` });
                    this.show(this.reloaded(updated));
                },
            },
        ]);
    }

    // enable enables or disables a certificate, once disabling is confirmed,
    // as it disables the certificates it signed
    private async enable(cert: Certificate, enabled: boolean) {
        if (!this.controller) {
            return;
        }
        if (!enabled && !confirm(certType(cert) === 'ca'
            ? `Disable ${cert.name}? The certificates it signed are disabled too.`
            : `Disable ${cert.name}? It's no longer returned.`)) {
            return;
        }
        const updated = await this.controller.update(cert, { enabled });
        this.notifications?.push({ kind: 'success', title: `${updated.name} was ${enabled ? 'enabled' : 'disabled'}` });
        this.show(this.reloaded(updated));
    }

    // download saves a certificate, with its issuers, up to the root, as PEM
    private async download(cert: Certificate) {
        try {
            const bundle = await this.controller!.bundle(cert);
            download(`${cert.name}.pem`, certificatePEM(bundle));
        } catch (error) {
            this.notifications?.error(`${cert.name} couldn't be downloaded`, error);
        }
    }

    // downloadKey saves a leaf certificate's private key, as PEM
    private async downloadKey(cert: Certificate) {
        try {
            const bundle = await this.controller!.privateKey(cert);
            download(`${cert.name}.key`, privateKeyPEM(bundle));
        } catch (error) {
            this.notifications?.error(`${cert.name}'s private key couldn't be downloaded`, error);
        }
    }

    // select opens a new certificate, such as one which was created or
    // renewed, in the list, so it's selected, rather than what was, and shows
    // it
    private select(cert: Certificate) {
        if ((certType(cert) === 'ca') === (this.kind === 'ca')) {
            this.controller?.list.open(cert);
        }
        this.show(cert);
    }

    // reloaded is the certificate as the list has it, once it's loaded again
    // after a change, when it's selected, or else the fallback
    private reloaded(fallback: Certificate): Certificate {
        const selected = this.controller?.list.current.selected;
        return selected && keyOf(selected) === keyOf(fallback) ? selected : fallback;
    }
}

if (!customElements.get(CertificatesTag)) {
    customElements.define(CertificatesTag, CertificatesElement);
}

declare global {
    interface HTMLElementTagNameMap {
        [CertificatesTag]: CertificatesElement;
    }
}

///////////////////////////////////////////////////////////////////////////////
// MODULE

// CertApp is what the module needs of the app which includes it: its
// navigation, its router, the certificate API's client, its notifications
// and changes, and the element its pages are added to
export interface CertApp {
    nav: NavController;
    router: Router;
    client: Client;
    root: HTMLElement;
    notifications?: NotificationController;
    changes?: ChangesController;
    // features are what the server's certificate manager can do, such as
    // from configSection(config, 'cert')
    features?: CertFeatures;
}

// CertPages are the module's pages: the leaf certificates, the certificate
// authorities, and the subjects
export interface CertPages {
    authorities: CertificatesElement;
    certificates: CertificatesElement;
    subjects: SubjectsElement;
}

// certModule adds the Certificates module to the app: its section, which
// owns the menu bar's Certificates item, and the sidebar while it's active,
// of its pages, Leaf Certificates, Certificate Authorities and Subjects,
// which it adds
// to the root, and routes to. A certificate authority's panel creates a
// certificate on the Leaf Certificates page. The pages' ids are prefixed
// with page-, not the hashes they're routed to, so the browser doesn't
// scroll to them.
export function certModule(app: CertApp, section = 'Certificates'): CertPages {
    const add = (id: string, kind: 'ca' | 'certificate') => {
        const page = document.createElement('section');
        page.id = `page-${id}`;
        page.className = 'page';
        page.hidden = true;

        const element = document.createElement(CertificatesTag);
        element.kind = kind;
        element.client = app.client;
        element.notifications = app.notifications;
        element.changes = app.changes;
        element.features = app.features;
        page.append(element);
        app.root.append(page);
        app.router.add(id, page);
        return element;
    };
    const certificates = add('certificates', 'certificate');
    const authorities = add('certificate-authorities', 'ca');

    // The subjects' page
    const page = document.createElement('section');
    page.id = 'page-subjects';
    page.className = 'page';
    page.hidden = true;
    const subjects = document.createElement(SubjectsTag);
    subjects.client = app.client;
    subjects.notifications = app.notifications;
    subjects.changes = app.changes;
    page.append(subjects);
    app.root.append(page);
    app.router.add('subjects', page);

    const pages = { certificates, authorities, subjects };
    pages.authorities.createCertificate = (signer) => {
        location.hash = '#certificates';
        void pages.certificates.createLeaf(signer);
    };

    app.nav.setSection(section, [
        { id: 'certificates', label: 'Leaf Certificates', href: '#certificates' },
        { id: 'certificate-authorities', label: 'Certificate Authorities', href: '#certificate-authorities' },
        { id: 'subjects', label: 'Subjects', href: '#subjects' },
    ]);
    return pages;
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// signerName is the name of a certificate's signer, which is Root for the
// root's
function signerName(cert: Certificate): string {
    if (!cert.signer) {
        return '';
    }
    return cert.signer.name === RootCertName ? 'Root' : cert.signer.name;
}

// keyOf is a certificate's version, as a string
function keyOf(cert: Certificate): string {
    return `${cert.name}/${cert.serial}`;
}

// typeTag is a tag of what the certificate is
function typeTag(cert: Certificate): TemplateResult {
    switch (certType(cert)) {
        case 'root':
            return html`<cds-tag type="purple" size="sm">Root</cds-tag>`;
        case 'ca':
            return html`<cds-tag type="blue" size="sm">Certificate authority</cds-tag>`;
        default:
            return html`<cds-tag type="gray" size="sm">Certificate</cds-tag>`;
    }
}

// stateTags are tags of a certificate which is disabled, or has expired
function stateTags(cert: Certificate): TemplateResult {
    return html`${cert.enabled === false ? html`<cds-tag type="red" size="sm">Disabled</cds-tag>` : nothing}${certExpired(cert)
        ? html`<cds-tag type="warm-gray" size="sm">Expired</cds-tag>`
        : nothing}`;
}

