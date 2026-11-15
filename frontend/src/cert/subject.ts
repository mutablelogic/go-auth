// ga-subjects is a page of the subjects which certificates are created with:
// its header, which creates one, the table of them, with the number of
// certificates which use each, and a panel, which opens one, and edits or
// deletes one which no certificate uses. It's given the API's client, and
// the app's notifications.

import { LitElement, html, nothing, type PropertyValues, type TemplateResult } from 'lit';
import type { Client } from '@mutablelogic/go-server/api';
import type { ChangesController } from '@mutablelogic/go-server/broadcaster';
import type { Column } from '@mutablelogic/go-server/list/view';
import type { NotificationController } from '@mutablelogic/go-server/notification';
import { PanelController, type PanelAction } from '@mutablelogic/go-server/panel';
import type { PageAction } from '@mutablelogic/go-server/page';
import { SubjectController } from './controller.ts';
import { SubjectFields, subjectCreateRequest, subjectUpdateRequest } from './form.ts';
import { formatTime, subjectView } from './parts.ts';
import type { Subject, SubjectMeta } from './schema.ts';

// go-server's and Carbon's elements
import '@mutablelogic/go-server/list/view';
import '@mutablelogic/go-server/page/view';
import '@mutablelogic/go-server/panel/view';
import AddIcon from '@carbon/icons/es/add/16.js';
import UserProfileIcon from '@carbon/icons/es/user--profile/32.js';

///////////////////////////////////////////////////////////////////////////////
// PARTS

// subjectColumns are the columns of a table of subjects: its identifier, its
// fields as a distinguished name, how many certificates use it, and when it
// was last changed
export const subjectColumns: Column<Subject>[] = [
    { header: 'ID', cell: (subject) => String(subject.id) },
    { header: 'Subject', cell: (subject) => subject.subject || '-' },
    { header: 'Certificates', cell: (subject) => String(subject.certs) },
    { header: 'Updated', cell: (subject) => formatTime(subject.timestamp) },
];

// subjectDetailsView shows a subject's fields, and whether it can be changed
export function subjectDetailsView(subject: Subject): TemplateResult {
    return html`
        <dl class="details">
            ${SubjectFields.map(({ field, label }) => html`<dt>${label}</dt><dd>${subject[field] || '-'}</dd>`)}
            <dt>Certificates</dt><dd>${subject.certs}</dd>
        </dl>
        <p class="helper" style="margin-top: 1rem">${usedBy(subject.certs)}</p>
    `;
}

///////////////////////////////////////////////////////////////////////////////
// PAGE

// SubjectsTag is the page element's tag
export const SubjectsTag = 'ga-subjects';

// Body is what the panel shows, and its kind, which says whether a form is
// open, so the panel isn't closed when the list's item is
interface Body {
    kind: 'subject' | 'form';
    content: TemplateResult;
    // id is the subject's, when it's one's, so the panel isn't shown again
    // when the list is loaded again, with the same one selected
    id?: number;
}

export class SubjectsElement extends LitElement {
    static override properties = {
        client: { attribute: false },
        controller: { attribute: false },
        notifications: { attribute: false },
        changes: { attribute: false },
        heading: { type: String },
        body: { state: true },
    };

    // client is the certificate API's client, which the controller is made
    // with, when it isn't given
    declare client?: Client;

    // controller keeps the subjects
    declare controller?: SubjectController;

    // notifications show what's done, and errors, and changes load the
    // subjects again, when they, or certificates, change
    declare notifications?: NotificationController;
    declare changes?: ChangesController;

    // heading is the page's title
    declare heading: string;

    // body is what the panel shows
    declare private body?: Body;

    private readonly panel = new PanelController<Body>();
    private unsubscribe?: () => void;

    constructor() {
        super();
        this.heading = 'Subjects';
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
            this.controller = new SubjectController(this.client, { notifications: this.notifications, changes: this.changes });
        }
        if (changed.has('controller') || changed.has('client')) {
            this.watch();
        }
    }

    protected override render() {
        if (!this.controller) {
            return nothing;
        }
        const actions: PageAction[] = [{ label: 'Create a subject', icon: AddIcon, run: () => this.edit() }];
        return html`
            <gs-page-header heading=${this.heading}
                subtitle="Which certificates are created with, other than their names, and share"
                .icon=${UserProfileIcon} .actions=${actions}></gs-page-header>
            <gs-table .controller=${this.controller.list} .columns=${subjectColumns}
                empty="No subjects are stored"></gs-table>
            <gs-panel .controller=${this.panel}>${this.body?.content ?? nothing}</gs-panel>
        `;
    }

    // watch opens a subject in the panel when it's opened in the table, and
    // closes the panel when it's closed, unless a form is open
    private watch() {
        this.unsubscribe?.();
        this.unsubscribe = this.isConnected ? this.controller?.list.subscribe(({ selected }) => {
            if (selected) {
                if (!this.panel.isOpen || this.body?.id !== selected.id || this.body.kind === 'subject') {
                    this.show(selected);
                }
            } else if (this.panel.isOpen && this.body?.kind === 'subject') {
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

    // show shows a subject, and edits or deletes it, when no certificate
    // uses it
    private show(subject: Subject) {
        const actions: PanelAction[] = subject.certs ? [] : [
            { label: 'Delete', kind: 'danger', close: false, run: () => this.delete(subject) },
            { label: 'Edit', kind: 'primary', close: false, run: () => this.edit(subject) },
        ];
        this.open(subject.subject || `Subject ${subject.id}`, `Subject ${subject.id}`, {
            kind: 'subject',
            id: subject.id,
            content: subjectDetailsView(subject),
        }, actions);
    }

    // edit shows the form which creates a subject, or edits one, and shows it
    private edit(subject?: Subject) {
        // The form has the selection's identifier, when one is selected, so
        // the list being loaded again doesn't show it in the form's place
        const id = this.controller?.list.current.selected?.id;
        const fields: SubjectMeta = {};
        for (const { field } of SubjectFields) {
            fields[field] = subject?.[field] ?? '';
        }
        const view = (error?: string) => html`
            <div class="form">
                ${subjectView(fields, subject ? 'An empty field is removed' : 'At least one field, which are trimmed')}
                ${error ? html`<p class="helper" style="color: var(--cds-text-error, #da1e28)">${error}</p>` : nothing}
            </div>
        `;
        const cancel: PanelAction = subject
            ? { label: 'Cancel', kind: 'secondary', close: false, run: () => this.show(subject) }
            : { label: 'Cancel', kind: 'secondary' };
        this.open(subject ? `Edit subject ${subject.id}` : 'Create a subject', 'Subject', { kind: 'form', id, content: view() }, [cancel, {
            label: subject ? 'Save' : 'Create',
            kind: 'primary',
            close: false,
            run: async () => {
                if (!this.controller) {
                    return;
                }
                const req = subject ? subjectUpdateRequest(subject, fields) : subjectCreateRequest(fields);
                if (!req) {
                    this.body = { kind: 'form', id, content: view(subject ? 'Change a field, and keep at least one' : 'Set at least one field') };
                    return;
                }
                const saved = subject ? await this.controller.update(subject.id, req) : await this.controller.create(req);
                this.notifications?.push({ kind: 'success', title: subject ? `Subject ${saved.id} was changed` : `Subject ${saved.id} was created` });
                this.controller.list.open(saved);
                this.show(saved);
            },
        }]);
    }

    // delete deletes a subject, once it's confirmed
    private async delete(subject: Subject) {
        if (!this.controller || !confirm(`Delete subject ${subject.id}?`)) {
            return;
        }
        await this.controller.delete(subject.id);
        this.notifications?.push({ kind: 'success', title: `Subject ${subject.id} was deleted` });
        this.panel.close();
    }
}

if (!customElements.get(SubjectsTag)) {
    customElements.define(SubjectsTag, SubjectsElement);
}

declare global {
    interface HTMLElementTagNameMap {
        [SubjectsTag]: SubjectsElement;
    }
}

// usedBy says how many certificates use a subject, and so whether it can be
// changed or deleted
function usedBy(certs: number): string {
    switch (certs) {
        case 0:
            return 'No certificate uses it, so it can be changed or deleted.';
        case 1:
            return "It's used by a certificate, which has it in it, so it can't be changed or deleted.";
        default:
            return `It's used by ${certs} certificates, which have it in them, so it can't be changed or deleted.`;
    }
}
