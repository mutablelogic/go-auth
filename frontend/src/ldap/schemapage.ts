// ga-ldap-schema is the LDAP module's Schema page: its header, with the
// directory's status, and two tabs, of the directory's object classes and
// attribute types, each a table, which is searched. A class, or attribute
// type, opens in a panel, with what it is, and the classes, or attributes,
// it refers to, which open in turn.

import { html, nothing, type PropertyValues, type TemplateResult } from 'lit';
import { until } from 'lit/directives/until.js';
import type { ListController } from '@mutablelogic/go-server/list';
import type { Column, TableSearch } from '@mutablelogic/go-server/list/view';
import { PanelController } from '@mutablelogic/go-server/panel';
import { SchemaController, schemaIs } from './controller.ts';
import { LdapPage } from './parts.ts';
import { syntaxName, type AttributeType, type ObjectClass } from './schema.ts';

// go-server's and Carbon's elements
import '@mutablelogic/go-server/list/view';
import '@mutablelogic/go-server/page/view';
import '@mutablelogic/go-server/panel/view';
import '@carbon/web-components/es/components/tabs/index.js';
import '@carbon/web-components/es/components/tag/index.js';
import SchemaIcon from '@carbon/icons/es/catalog/32.js';

///////////////////////////////////////////////////////////////////////////////
// PARTS

export const LdapSchemaTag = 'ga-ldap-schema';

// SchemaTab is which of the page's tabs is shown
export type SchemaTab = 'classes' | 'attributes';

// nameOf returns a class's, or attribute type's, first name, or its OID
function nameOf(item: ObjectClass | AttributeType): string {
    return item.name?.[0] ?? item.numericOid;
}

// The tag of a class's kind
const KindTags: Record<string, string> = { STRUCTURAL: 'blue', AUXILIARY: 'teal', ABSTRACT: 'gray' };

// classColumns are the columns of a table of object classes: the name, its
// kind, the classes it inherits from, and how many attributes it must, and
// may, have
export const classColumns: Column<ObjectClass>[] = [
    { header: 'Name', cell: (c) => html`${nameOf(c)}${c.obsolete ? html` <cds-tag size="sm" type="red">Obsolete</cds-tag>` : nothing}` },
    { header: 'Kind', cell: (c) => html`<cds-tag size="sm" type=${KindTags[c.classKind ?? 'STRUCTURAL'] ?? 'gray'}>${(c.classKind ?? 'STRUCTURAL').toLowerCase()}</cds-tag>` },
    { header: 'Inherits from', cell: (c) => (c.superClasses ?? []).join(', ') },
    { header: 'Must', cell: (c) => String(c.must?.length ?? 0) },
    { header: 'May', cell: (c) => String(c.may?.length ?? 0) },
];

// attributeColumns are the columns of a table of attribute types: the name,
// its syntax, whether it has one value, and its usage, which is only said
// when it isn't the user's
export const attributeColumns: Column<AttributeType>[] = [
    { header: 'Name', cell: (a) => html`${nameOf(a)}${a.obsolete ? html` <cds-tag size="sm" type="red">Obsolete</cds-tag>` : nothing}` },
    { header: 'Syntax', cell: (a) => a.syntax ? syntaxName(a.syntax) : a.superType ? `As ${a.superType}` : '' },
    { header: 'Values', cell: (a) => a.singleValue ? 'One' : 'Any' },
    { header: 'Usage', cell: (a) => a.usage && a.usage !== 'userApplications' ? a.usage : '' },
];

///////////////////////////////////////////////////////////////////////////////
// PAGE

// Body is what the panel shows: a class, or attribute type, by its OID
interface Body {
    kind: 'class' | 'attribute';
    oid: string;
    content: TemplateResult;
}

export class LdapSchemaElement extends LdapPage {
    static override properties = {
        ...LdapPage.properties,
        controller: { attribute: false },
        heading: { type: String },
        tab: { type: String },
        body: { state: true },
    };

    // controller keeps the schema, which is made with the client, when it
    // isn't given
    declare controller?: SchemaController;
    declare heading: string;
    declare tab: SchemaTab;
    declare private body?: Body;

    private readonly panel = new PanelController<{ oid: string }>();
    private unsubscribe: (() => void)[] = [];

    // opened counts what's opened in the panel, so a class, or attribute,
    // found after another was opened, isn't shown
    private opened = 0;

    constructor() {
        super();
        this.heading = 'Schema';
        this.tab = 'classes';
        this.panel.onClose(() => {
            this.opened++;
            this.controller?.classes.close();
            this.controller?.attributes.close();
        });
        this.panel.onError((error, action) => this.notifications?.error(`${action.label} didn't work`, error));
    }

    override connectedCallback(): void {
        super.connectedCallback();
        this.watch();
    }

    override disconnectedCallback(): void {
        this.unsubscribe.forEach((fn) => fn());
        this.unsubscribe = [];
        super.disconnectedCallback();
    }

    protected override willUpdate(changed: PropertyValues<this>): void {
        if (!this.controller && this.client) {
            this.controller = new SchemaController(this.client, { notifications: this.notifications, changes: this.changes });
        }
        if (changed.has('controller') || changed.has('client')) {
            this.watch();
        }
    }

    protected override render() {
        if (!this.controller) {
            return nothing;
        }
        const controller = this.controller;
        return html`
            <gs-page-header heading=${this.heading} .icon=${SchemaIcon} .details=${this.details}></gs-page-header>
            <cds-tabs value=${this.tab} @cds-tabs-selected=${(event: CustomEvent<{ item: { value: string } }>) => {
                this.tab = event.detail.item.value as SchemaTab;
            }}>
                <cds-tab value="classes">Object classes</cds-tab>
                <cds-tab value="attributes">Attribute types</cds-tab>
            </cds-tabs>
            <div style="margin-top: 1rem">
                ${this.tab === 'classes' ? html`
                    <gs-table .controller=${controller.classes} .columns=${classColumns} .itemKey=${(c: ObjectClass) => c.numericOid}
                        search="Search object classes"
                        @gs-table-search=${(event: CustomEvent<TableSearch>) => { void controller.setClassSearch(event.detail.value).then(() => this.requestUpdate()); }}
                        empty=${controller.classSearch ? 'No object classes match' : 'No object classes'}></gs-table>
                ` : html`
                    <gs-table .controller=${controller.attributes} .columns=${attributeColumns} .itemKey=${(a: AttributeType) => a.numericOid}
                        search="Search attribute types"
                        @gs-table-search=${(event: CustomEvent<TableSearch>) => { void controller.setAttributeSearch(event.detail.value).then(() => this.requestUpdate()); }}
                        empty=${controller.attributeSearch ? 'No attribute types match' : 'No attribute types'}></gs-table>
                `}
            </div>
            <gs-panel .controller=${this.panel}>${this.body?.content ?? nothing}</gs-panel>
        `;
    }

    // watch opens a class, or attribute type, in the panel when it's opened
    // in its table, and closes the panel when the one it shows is closed
    private watch() {
        this.unsubscribe.forEach((fn) => fn());
        this.unsubscribe = [];
        if (!this.isConnected || !this.controller) {
            return;
        }
        const follow = <T extends ObjectClass | AttributeType>(list: ListController<T>, show: (item: T) => void) => {
            let previous: T | undefined;
            return list.subscribe(({ selected }) => {
                if (selected) {
                    if (!this.panel.isOpen || !this.body || !schemaIs(selected, this.body.oid)) {
                        show(selected);
                    }
                } else if (previous && this.panel.isOpen && this.body && schemaIs(previous, this.body.oid)) {
                    this.panel.close();
                }
                previous = selected;
            });
        };
        this.unsubscribe.push(
            follow(this.controller.classes, (c) => this.showClass(c)),
            follow(this.controller.attributes, (a) => this.showAttribute(a)),
            this.controller.onReload(() => void this.rebuild()),
        );
    }

    // rebuild shows the class, or attribute type, the panel shows again, as
    // the schema has been read again, however it was opened, or closes the
    // panel, when the directory no longer has it
    private async rebuild() {
        const body = this.body;
        if (!this.panel.isOpen || !body || !this.controller) {
            return;
        }
        const opened = this.opened;
        const found = body.kind === 'class' ? await this.controller.find('class', body.oid) : await this.controller.find('attribute', body.oid);
        if (this.opened !== opened || !this.panel.isOpen) {
            return;
        } else if (!found) {
            this.panel.close();
        } else if (body.kind === 'class') {
            this.showClass(found as ObjectClass, false);
        } else {
            this.showAttribute(found as AttributeType, false);
        }
    }

    // open shows the body in the panel, with its header, and opens it, or
    // else shows it again, in the panel which is open
    private open(title: string, subtitle: string, body: Body, open = true) {
        this.body = body;
        this.panel.setHeader({ title, subtitle });
        this.panel.setActions([]);
        if (open) {
            this.opened++;
            this.panel.open({ oid: body.oid });
        }
    }

    // showClass shows an object class: its names, OID, kind, description,
    // the classes it inherits from, and the attributes it must, and may,
    // have, which open when they're clicked
    private showClass(c: ObjectClass, open = true) {
        this.open(nameOf(c), `${(c.classKind ?? 'STRUCTURAL').toLowerCase()} object class`, {
            kind: 'class',
            oid: c.numericOid,
            content: html`
                ${c.description ? html`<p class="description">${c.description}</p>` : nothing}
                <dl class="details">
                    <dt>OID</dt><dd><code>${c.numericOid}</code></dd>
                    ${(c.name?.length ?? 0) > 1 ? html`<dt>Also</dt><dd>${c.name!.slice(1).join(', ')}</dd>` : nothing}
                    ${c.obsolete ? html`<dt>Obsolete</dt><dd>Yes</dd>` : nothing}
                    <dt>Inherits from</dt><dd>${this.links('class', c.superClasses)}</dd>
                    <dt>Must have</dt><dd>${this.links('attribute', c.must)}</dd>
                    <dt>May have</dt><dd>${this.links('attribute', c.may)}</dd>
                </dl>
            `,
        }, open);
    }

    // showAttribute shows an attribute type: its names, OID, description,
    // syntax, the type it inherits from, its flags, and the classes which
    // must, or may, have it
    private showAttribute(a: AttributeType, open = true) {
        const usedBy = this.usedBy(a);
        this.open(nameOf(a), 'Attribute type', {
            kind: 'attribute',
            oid: a.numericOid,
            content: html`
                ${a.description ? html`<p class="description">${a.description}</p>` : nothing}
                <dl class="details">
                    <dt>OID</dt><dd><code>${a.numericOid}</code></dd>
                    ${(a.name?.length ?? 0) > 1 ? html`<dt>Also</dt><dd>${a.name!.slice(1).join(', ')}</dd>` : nothing}
                    ${a.superType ? html`<dt>Inherits from</dt><dd>${this.links('attribute', [a.superType])}</dd>` : nothing}
                    <dt>Syntax</dt><dd>${this.syntaxView(a)}</dd>
                    <dt>Values</dt><dd>${a.singleValue ? 'One' : 'Any number'}</dd>
                    <dt>Usage</dt><dd>${a.usage ?? 'userApplications'}</dd>
                    ${a.noUserModification ? html`<dt>Changed</dt><dd>Only by the directory</dd>` : nothing}
                    ${a.collective ? html`<dt>Collective</dt><dd>Yes</dd>` : nothing}
                    ${a.obsolete ? html`<dt>Obsolete</dt><dd>Yes</dd>` : nothing}
                    <dt>Used by</dt><dd>${usedBy}</dd>
                </dl>
            `,
        }, open);
    }

    // syntaxView is an attribute's syntax, by name, and OID, and the type
    // it's from, when it's inherited
    private syntaxView(a: AttributeType): unknown {
        const syntax = this.controller?.syntaxOf(a);
        return syntax ? until(syntax.then((found) => found
            ? html`${syntaxName(found.syntax)} <code>${found.syntax}</code>${found.from ? html`, from ${found.from}` : nothing}`
            : 'Unknown'), nothing) : nothing;
    }

    // usedBy is the classes which must, or may, have the attribute, once
    // they're found
    private usedBy(a: AttributeType): unknown {
        const names = new Set((a.name ?? []).concat(a.numericOid).map((n) => n.toLowerCase()));
        const uses = (list?: string[]) => (list ?? []).some((n) => names.has(n.toLowerCase()));
        const classes = this.controller?.allClasses().then((all) => all.filter((c) => uses(c.must) || uses(c.may)).map(nameOf));
        return classes ? html`${until(classes.then((found) => found.length ? this.links('class', found) : 'No class'), nothing)}` : nothing;
    }

    // links are the names of classes, or attribute types, as tags in
    // buttons, which open them when they're clicked, or chosen with the
    // keyboard
    private links(kind: 'class' | 'attribute', names?: string[]): TemplateResult {
        if (!names?.length) {
            return html`None`;
        }
        return html`
            <span style="display: inline-flex; flex-wrap: wrap; gap: 0.25rem">
                ${names.map((name) => html`<button type="button" title=${`Open ${name}`} aria-label=${`Open ${name}`}
                    style="all: unset; cursor: pointer; display: inline-flex; border-radius: 1rem; outline-offset: 2px"
                    @click=${() => void this.follow(kind, name)}><cds-tag size="sm" type=${kind === 'class' ? 'blue' : 'cool-gray'}
                    style="pointer-events: none; margin: 0">${name}</cds-tag></button>`)}
            </span>
        `;
    }

    // follow opens the class, or attribute type, with the name, in its tab,
    // rather than the one which is selected in a table
    private async follow(kind: 'class' | 'attribute', name: string) {
        if (!this.controller) {
            return;
        }
        const opened = this.opened;
        const found = kind === 'class' ? await this.controller.find('class', name) : await this.controller.find('attribute', name);
        if (this.opened !== opened) {
            return;
        } else if (!found) {
            this.notifications?.push({ kind: 'info', title: `The directory has no ${kind === 'class' ? 'object class' : 'attribute type'} ${name}` });
            return;
        }
        this.controller.classes.close();
        this.controller.attributes.close();
        this.tab = kind === 'class' ? 'classes' : 'attributes';
        if (kind === 'class') {
            this.showClass(found as ObjectClass);
        } else {
            this.showAttribute(found as AttributeType);
        }
    }
}

if (!customElements.get(LdapSchemaTag)) {
    customElements.define(LdapSchemaTag, LdapSchemaElement);
}

declare global {
    interface HTMLElementTagNameMap {
        [LdapSchemaTag]: LdapSchemaElement;
    }
}
