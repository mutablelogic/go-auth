// ga-ldap-objects is the LDAP module's Objects page: its header, with the
// directory's status, a tree of the directory's entries, from its base DN,
// whose children are loaded when they're expanded, and loaded again when
// entries change, and a panel, which opens an entry, with its attributes,
// and deletes it

import { html, nothing, type PropertyValues, type TemplateResult } from 'lit';
import { repeat } from 'lit/directives/repeat.js';
import { PanelController, type PanelAction } from '@mutablelogic/go-server/panel';
import { ObjectController } from './controller.ts';
import * as api from './httpclient.ts';
import { LdapPage, attrsView } from './parts.ts';
import { dnKey, entryKind, hasChildren, parentDN, rdn, sameDN, values, type LdapObject } from './schema.ts';

// go-server's and Carbon's elements
import '@mutablelogic/go-server/page/view';
import '@mutablelogic/go-server/panel/view';
import '@carbon/web-components/es/components/tree-view/index.js';
import iconLoader from '@carbon/web-components/es/globals/internal/icon-loader.js';
import ContainerIcon from '@carbon/icons/es/folder/16.js';
import PersonIcon from '@carbon/icons/es/user/16.js';
import GroupIcon from '@carbon/icons/es/events/16.js';
import EntryIcon from '@carbon/icons/es/document/16.js';
import ObjectsIcon from '@carbon/icons/es/tree-view--alt/32.js';

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

export const LdapObjectsTag = 'ga-ldap-objects';

// The icons of entries, by what they are
const Icons = {
    container: iconLoader(ContainerIcon, { slot: 'icon' }),
    person: iconLoader(PersonIcon, { slot: 'icon' }),
    group: iconLoader(GroupIcon, { slot: 'icon' }),
    entry: iconLoader(EntryIcon, { slot: 'icon' }),
};

// Children are an entry's children: loading, loaded, or not, when they
// couldn't be
type Children = { state: 'loading' } | { state: 'loaded'; entries: LdapObject[] } | { state: 'error' };

///////////////////////////////////////////////////////////////////////////////
// PAGE

export class LdapObjectsElement extends LdapPage {
    static override properties = {
        ...LdapPage.properties,
        controller: { attribute: false },
        heading: { type: String },
        body: { state: true },
        version: { state: true },
    };

    // controller loads the entries, which is made with the client, when it
    // isn't given
    declare controller?: ObjectController;
    declare heading: string;
    declare private body?: { dn: string; content: TemplateResult };

    // version is changed when the tree changes, so it's rendered again
    declare private version: number;

    // The entries' children, and which entries are expanded, and selected,
    // by their DNs' keys
    private readonly loaded = new Map<string, Children>();
    private readonly expanded = new Set<string>();
    private selected?: string;

    private readonly panel = new PanelController<{ dn: string }>();
    private unsubscribe?: () => void;

    // opened counts what's opened in the panel, so a response which arrives
    // after what it was for was closed, or another opened, is ignored
    private opened = 0;

    constructor() {
        super();
        this.heading = 'Objects';
        this.version = 0;
        this.panel.onClose(() => {
            this.opened++;
            this.selected = undefined;
            this.version++;
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
            this.controller = new ObjectController(this.client, { notifications: this.notifications, changes: this.changes });
        }
        if (changed.has('controller') || changed.has('client')) {
            this.watch();
        }

        // The base DN is expanded, and its children loaded, once it's known
        const base = this.current?.base_dn;
        if (base && this.controller && !this.loaded.has(dnKey(base))) {
            this.expanded.add(dnKey(base));
            void this.load(base);
        }
    }

    protected override render() {
        const base = this.current?.base_dn;
        return html`
            <gs-page-header heading=${this.heading} .icon=${ObjectsIcon} .details=${this.details}></gs-page-header>
            ${base ? html`
                <cds-tree-view label="Directory" hide-label size="sm"
                    @cds-tree-node-toggled=${(event: CustomEvent<{ expanded: boolean }>) => this.toggled(event)}
                    @cds-tree-node-selected=${(event: Event) => this.selectedNode(event)}>
                    ${this.nodeView(base, base)}
                </cds-tree-view>
            ` : nothing}
            <gs-panel .controller=${this.panel}>${this.body?.content ?? nothing}</gs-panel>
        `;
    }

    // nodeView is an entry's node, and, when it's expanded, its children's,
    // or a node which says they're loading, so it can be expanded. An entry
    // which has no children has no caret.
    private nodeView(dn: string, label: string, entry?: LdapObject): TemplateResult {
        const key = dnKey(dn);
        const children = this.loaded.get(key);
        const leaf = (entry && hasChildren(entry) === false) || (children?.state === 'loaded' && children.entries.length === 0);
        return html`
            <cds-tree-node label=${label} data-dn=${dn} .isExpanded=${!leaf && this.expanded.has(key)} .selected=${this.selected === key}>
                ${Icons[entry ? entryKind(entry) : 'container']}
                ${leaf ? nothing : children?.state === 'loaded'
                    ? repeat(children.entries, (child) => dnKey(child.dn), (child) => this.nodeView(child.dn, rdn(child.dn), child))
                    : html`<cds-tree-node label=${children?.state === 'error' ? "They couldn't be loaded" : 'Loading…'} disabled></cds-tree-node>`}
            </cds-tree-node>
        `;
    }

    // toggled loads an entry's children when it's expanded, the first time
    private toggled(event: CustomEvent<{ expanded: boolean }>) {
        const dn = nodeDN(event);
        if (!dn) {
            return;
        }
        const key = dnKey(dn);
        if (event.detail.expanded) {
            this.expanded.add(key);
            if (this.loaded.get(key)?.state !== 'loaded') {
                void this.load(dn);
            }
        } else {
            this.expanded.delete(key);
        }
    }

    // selectedNode opens the entry which is selected in the panel
    private selectedNode(event: Event) {
        const dn = nodeDN(event);
        if (!dn || this.selected === dnKey(dn)) {
            return;
        }
        this.selected = dnKey(dn);
        void this.openEntry(dn);
    }

    // load loads the entry's children, which are kept as they are, while
    // they're loaded again
    private async load(dn: string) {
        const key = dnKey(dn);
        if (!this.controller) {
            return;
        }
        if (this.loaded.get(key)?.state !== 'loaded') {
            this.loaded.set(key, { state: 'loading' });
            this.version++;
        }
        try {
            const base = this.current?.base_dn;
            const entries = await this.controller.children(base && sameDN(base, dn) ? undefined : dn);
            this.loaded.set(key, { state: 'loaded', entries });
        } catch (error) {
            this.notifications?.error(`The entries under ${dn} couldn't be loaded`, error);
            this.loaded.set(key, { state: 'error' });
        }
        this.version++;
    }

    // watch loads what the tree shows again, and the entry the panel shows,
    // when entries change
    private watch() {
        this.unsubscribe?.();
        this.unsubscribe = this.isConnected ? this.controller?.onChange(() => void this.reload()) : undefined;
    }

    // reload loads the children of the entries which are expanded again, and
    // forgets the others', so they're loaded when they're expanded, and the
    // entry the panel shows, or closes it, when it's gone
    private async reload() {
        for (const key of [...this.loaded.keys()]) {
            if (!this.expanded.has(key)) {
                this.loaded.delete(key);
            }
        }
        const loads: Promise<void>[] = [];
        for (const [key, children] of this.loaded) {
            if (children.state === 'loaded') {
                loads.push(this.load(this.dnOf(key) ?? key));
            }
        }
        await Promise.all(loads);
        if (this.panel.isOpen && this.body) {
            const opened = this.opened;
            const dn = this.body.dn;
            try {
                const entry = await api.getObject(this.controller!.client, dn);
                if (this.opened === opened && this.panel.isOpen) {
                    this.show(entry, false);
                }
            } catch {
                if (this.opened === opened && this.panel.isOpen) {
                    this.panel.close();
                }
            }
        }
    }

    // dnOf returns the DN of an entry the tree has, by its key, or the base
    // DN's
    private dnOf(key: string): string | undefined {
        const base = this.current?.base_dn;
        if (base && dnKey(base) === key) {
            return base;
        }
        for (const children of this.loaded.values()) {
            if (children.state === 'loaded') {
                const found = children.entries.find((entry) => dnKey(entry.dn) === key);
                if (found) {
                    return found.dn;
                }
            }
        }
        return undefined;
    }

    // openEntry loads the entry, with its attributes, and shows it
    private async openEntry(dn: string) {
        if (!this.controller) {
            return;
        }
        this.opened++;
        const opened = this.opened;
        try {
            const entry = await this.controller.get(dn);
            if (this.opened === opened) {
                this.show(entry, true);
            }
        } catch (error) {
            this.notifications?.error(`${dn} couldn't be loaded`, error);
        }
    }

    // show shows an entry's attributes, and what can be done with it
    private show(entry: LdapObject, open: boolean) {
        const classes = values(entry, 'objectClass').filter((v): v is string => typeof v === 'string' && v.toLowerCase() !== 'top');
        this.body = { dn: entry.dn, content: attrsView(entry) };
        this.panel.setHeader({ title: rdn(entry.dn), subtitle: classes.join(', ') || 'Entry' });
        const actions: PanelAction[] = [
            { label: 'Delete', kind: 'danger', close: false, run: () => this.delete(entry) },
        ];
        this.panel.setActions(actions);
        if (open) {
            this.opened++;
            this.panel.open({ dn: entry.dn });
        }
    }

    // delete deletes an entry, which has no children, once it's confirmed,
    // and loads its parent's children again
    private async delete(entry: LdapObject) {
        if (!this.controller || !confirm(`Delete ${entry.dn}? Only an entry without entries under it can be deleted.`)) {
            return;
        }
        const opened = this.opened;
        await api.deleteObject(this.controller.client, entry.dn);
        this.notifications?.push({ kind: 'success', title: `${rdn(entry.dn)} was deleted` });
        if (this.opened === opened && this.panel.isOpen) {
            this.panel.close();
        }
        const parent = parentDN(entry.dn);
        if (this.loaded.has(dnKey(parent))) {
            await this.load(parent);
        }
    }
}

if (!customElements.get(LdapObjectsTag)) {
    customElements.define(LdapObjectsTag, LdapObjectsElement);
}

declare global {
    interface HTMLElementTagNameMap {
        [LdapObjectsTag]: LdapObjectsElement;
    }
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// nodeDN returns the DN of the node an event is from, which is the first
// node on its path, or none, for a node without one, such as one which says
// its parent's children are loading, which isn't its parent's event
function nodeDN(event: Event): string | undefined {
    for (const target of event.composedPath()) {
        if (target instanceof HTMLElement && target.tagName === 'CDS-TREE-NODE') {
            return target.dataset.dn || undefined;
        }
    }
    return undefined;
}
