// ga-ldap-objects is the LDAP module's Objects page: its header, with the
// directory's status, and two panes. On the left, a tree of the directory's
// branches, such as organizational units, from its base DN, whose children
// are loaded when they're expanded, or selected. On the right, a table of
// the selected branch's leaves, such as people. An entry, either, opens in a
// panel, with its attributes, which deletes it. What's shown is loaded again
// when entries change.

import { html, nothing, type PropertyValues, type TemplateResult } from 'lit';
import { repeat } from 'lit/directives/repeat.js';
import { ApiError } from '@mutablelogic/go-server/api';
import { ListController } from '@mutablelogic/go-server/list';
import type { Column, TableActionError, TableSearch, TableToolbarAction } from '@mutablelogic/go-server/list/view';
import { PanelController, type PanelAction } from '@mutablelogic/go-server/panel';
import { ObjectController } from './controller.ts';
import * as api from './httpclient.ts';
import { LdapPage, attrsView } from './parts.ts';
import { dnKey, entryKind, hasChildren, isBranch, isCounter, parentDN, rdn, sameDN, values, type LdapObject } from './schema.ts';

// go-server's and Carbon's elements
import '@mutablelogic/go-server/list/view';
import '@mutablelogic/go-server/page/view';
import '@mutablelogic/go-server/panel/view';
import '@carbon/web-components/es/components/tree-view/index.js';
import iconLoader from '@carbon/web-components/es/globals/internal/icon-loader.js';
import ContainerIcon from '@carbon/icons/es/folder/16.js';
import PersonIcon from '@carbon/icons/es/user/16.js';
import GroupIcon from '@carbon/icons/es/events/16.js';
import EntryIcon from '@carbon/icons/es/document/16.js';
import DetailsIcon from '@carbon/icons/es/information/16.js';
import ObjectsIcon from '@carbon/icons/es/tree-view--alt/32.js';

///////////////////////////////////////////////////////////////////////////////
// PARTS

export const LdapObjectsTag = 'ga-ldap-objects';

// The icons of entries, by what they are, in the table, and in the tree
const Icons = {
    container: ContainerIcon,
    person: PersonIcon,
    group: GroupIcon,
    entry: EntryIcon,
};
const SlotIcons = {
    container: iconLoader(ContainerIcon, { slot: 'icon' }),
    person: iconLoader(PersonIcon, { slot: 'icon' }),
    group: iconLoader(GroupIcon, { slot: 'icon' }),
    entry: iconLoader(EntryIcon, { slot: 'icon' }),
};

// entryColumns are the columns of a table of entries: the RDN, with its
// icon, and its object classes, other than top
export const entryColumns: Column<LdapObject>[] = [
    {
        header: 'Name',
        cell: (entry) => html`<span style="display: inline-flex; align-items: center; gap: 0.5rem">${iconLoader(Icons[entryKind(entry)])}${rdn(entry.dn)}</span>`,
    },
    { header: 'Classes', cell: (entry) => classesOf(entry).join(', ') },
];

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

    // The entries' children, which entries are expanded, by their DNs'
    // keys, and the branch which is selected, whose leaves are shown
    private readonly loaded = new Map<string, Children>();

    // The latest load of each entry's children, and its count, so an older
    // response, which a newer load replaced, isn't kept
    private readonly loading = new Map<string, { generation: number; done: Promise<void> }>();
    private generation = 0;
    private readonly expanded = new Set<string>();
    private branch?: string;

    // leaves are the selected branch's leaves, a page at a time, of those
    // whose names have the search's text
    private readonly leaves: ListController<LdapObject>;
    private search = '';

    private readonly panel = new PanelController<{ dn: string }>();
    private unsubscribe?: () => void;
    private unsubscribeLeaves?: () => void;

    // opened counts what's opened in the panel, so a response which arrives
    // after what it was for was closed, or another opened, is ignored
    private opened = 0;

    constructor() {
        super();
        this.heading = 'Objects';
        this.version = 0;
        this.leaves = new ListController<LdapObject>({
            name: 'Entries',
            list: async (offset, limit) => {
                const search = this.search.toLowerCase();
                const leaves = (await this.childrenOf(this.branch))
                    .filter((entry) => !isBranch(entry) && (!search || rdn(entry.dn).toLowerCase().includes(search)));
                return { count: leaves.length, body: leaves.slice(offset, offset + limit) };
            },
            get: (entry) => this.controller ? this.controller.get(entry.dn) : Promise.resolve(entry),
            same: (a, b) => sameDN(a.dn, b.dn),
        });
        this.panel.onClose(() => {
            this.opened++;
            this.leaves.close();
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
        this.unsubscribeLeaves?.();
        this.unsubscribeLeaves = undefined;
        super.disconnectedCallback();
    }

    protected override willUpdate(changed: PropertyValues<this>): void {
        if (!this.controller && this.client) {
            this.controller = new ObjectController(this.client, { notifications: this.notifications, changes: this.changes });
        }
        if (changed.has('controller') || changed.has('client')) {
            this.watch();
        }

        // The base DN is expanded, and selected, once it's known
        const base = this.current?.base_dn;
        if (base && this.controller && !this.branch) {
            this.expanded.add(dnKey(base));
            this.selectBranch(base);
        }
    }

    protected override render() {
        const base = this.current?.base_dn;
        const branch = this.branch;
        const tools: TableToolbarAction[] = branch
            ? [{ label: `Details of ${rdn(branch)}`, kind: 'ghost', icon: DetailsIcon, run: () => this.openEntry(branch) }]
            : [];
        return html`
            <gs-page-header heading=${this.heading} .icon=${ObjectsIcon} .details=${this.details}></gs-page-header>
            ${base ? html`
                <div style="display: flex; flex-wrap: wrap; gap: 1.5rem; align-items: flex-start">
                    <!-- Nodes are chosen, not text, which Carbon only shows for nodes with links -->
                    <cds-tree-view label="Branches" hide-label size="sm" style="flex: 0 1 20rem; min-width: 14rem; max-width: 100%; overflow-x: auto; cursor: pointer; user-select: none"
                        @cds-tree-node-toggled=${(event: CustomEvent<{ expanded: boolean }>) => this.toggled(event)}
                        @cds-tree-node-selected=${(event: Event) => this.selectedNode(event)}>
                        ${this.nodeView(base, base)}
                    </cds-tree-view>
                    <div style="flex: 1 1 28rem; min-width: 0">
                        <gs-table .controller=${this.leaves} .columns=${entryColumns} .itemKey=${(entry: LdapObject) => dnKey(entry.dn)}
                            search=${`Search ${branch ? rdn(branch) : 'entries'}`} .toolbarActions=${tools}
                            @gs-table-search=${(event: CustomEvent<TableSearch>) => {
                                this.search = event.detail.value.trim();
                                void this.leaves.reset();
                            }}
                            @gs-table-action-error=${(event: CustomEvent<TableActionError<LdapObject>>) => this.notifications?.error(`${event.detail.action.label} didn't work`, event.detail.error)}
                            empty=${this.search ? 'No entries match' : 'No entries, other than branches'}></gs-table>
                    </div>
                </div>
            ` : nothing}
            <gs-panel .controller=${this.panel}>${this.body?.content ?? nothing}</gs-panel>
        `;
    }

    // nodeView is a branch's node, and, when it's expanded, its branches'.
    // One which may have branches, but whose children aren't loaded, has a
    // node which says they're loading, so it can be expanded; one without
    // has no caret.
    private nodeView(dn: string, label: string, entry?: LdapObject): TemplateResult {
        const key = dnKey(dn);
        const children = this.loaded.get(key);
        const branches = children?.state === 'loaded' ? children.entries.filter(isBranch) : undefined;
        const leaf = (entry && hasChildren(entry) === false) || branches?.length === 0;
        return html`
            <cds-tree-node label=${label} data-dn=${dn} .isExpanded=${!leaf && this.expanded.has(key)} .selected=${this.branch !== undefined && dnKey(this.branch) === key}>
                ${SlotIcons[entry ? entryKind(entry) : 'container']}
                ${leaf ? nothing : branches
                    ? repeat(branches, (child) => dnKey(child.dn), (child) => this.nodeView(child.dn, rdn(child.dn), child))
                    : html`<cds-tree-node label=${children?.state === 'error' ? "They couldn't be loaded" : 'Loading…'} disabled style="cursor: default"></cds-tree-node>`}
            </cds-tree-node>
        `;
    }

    // toggled loads a branch's children when it's expanded, the first time
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

    // selectedNode shows the selected branch's leaves
    private selectedNode(event: Event) {
        const dn = nodeDN(event);
        if (dn && (!this.branch || !sameDN(this.branch, dn))) {
            this.selectBranch(dn);
        }
    }

    // selectBranch shows the branch's leaves, from the first page, without a
    // search, once its children are loaded
    private selectBranch(dn: string) {
        this.branch = dn;
        this.search = '';
        this.leaves.close();
        this.version++;
        void this.leaves.reset();
    }

    // childrenOf returns a branch's children, which are loaded when they
    // aren't
    private async childrenOf(dn?: string): Promise<LdapObject[]> {
        if (!dn) {
            return [];
        }
        // They're loaded, unless they are, or are loading, when the latest
        // load is waited for, until there's none
        const key = dnKey(dn);
        if (this.loaded.get(key)?.state !== 'loaded' && !this.loading.has(key)) {
            void this.load(dn);
        }
        for (let pending = this.loading.get(key); pending; pending = this.loading.get(key)) {
            await pending.done;
        }
        const children = this.loaded.get(key);
        return children?.state === 'loaded' ? children.entries : [];
    }

    // load loads the entry's children, which are kept as they are, while
    // they're loaded again
    private load(dn: string): Promise<void> {
        const key = dnKey(dn);
        const controller = this.controller;
        if (!controller) {
            return Promise.resolve();
        }
        if (this.loaded.get(key)?.state !== 'loaded') {
            this.loaded.set(key, { state: 'loading' });
            this.version++;
        }
        const generation = ++this.generation;
        const latest = () => this.loading.get(key)?.generation === generation;
        const done = (async () => {
            const base = this.current?.base_dn;
            try {
                const entries = await controller.children(base && sameDN(base, dn) ? undefined : dn);
                if (latest()) {
                    this.loaded.set(key, { state: 'loaded', entries });
                }
            } catch (error) {
                if (latest()) {
                    this.notifications?.error(`The entries under ${dn} couldn't be loaded`, error);
                    this.loaded.set(key, { state: 'error' });
                }
            }
            if (latest()) {
                this.loading.delete(key);
                this.version++;
            }
        })();
        this.loading.set(key, { generation, done });
        return done;
    }

    // watch loads what's shown again, when entries change, and opens a leaf
    // in the panel when it's opened in the table, and closes the panel when
    // it's closed, unless it shows the branch
    private watch() {
        this.unsubscribe?.();
        this.unsubscribe = this.isConnected ? this.controller?.onChange(() => void this.reload()) : undefined;
        this.unsubscribeLeaves?.();
        this.unsubscribeLeaves = this.isConnected ? this.leaves.subscribe(({ selected }) => {
            if (selected) {
                if (!this.panel.isOpen || !this.body || !sameDN(this.body.dn, selected.dn)) {
                    this.show(selected, true);
                }
            } else if (this.panel.isOpen && this.body && !(this.branch && sameDN(this.body.dn, this.branch))) {
                this.panel.close();
            }
        }) : undefined;
    }

    // reload loads the children of the branches which are expanded, or
    // selected, again, and forgets the others', so they're loaded when
    // they're needed, then the leaves, and the entry the panel shows, or
    // closes it, when it's gone. A load which was already running is
    // replaced, as it may be from before the change.
    private async reload() {
        const keep = new Set(this.expanded);
        if (this.branch) {
            keep.add(dnKey(this.branch));
        }
        const dns: string[] = [];
        // Those which are loading, or couldn't be loaded, such as while the
        // directory was disconnected, are loaded again too
        for (const key of [...this.loaded.keys()]) {
            const dn = this.dnOf(key);
            if (!keep.has(key) || !dn) {
                this.loaded.delete(key);
                this.loading.delete(key);
            } else {
                dns.push(dn);
            }
        }
        await Promise.all(dns.map((dn) => this.load(dn)));
        await this.leaves.refresh();
        if (this.panel.isOpen && this.body && this.controller) {
            const opened = this.opened;
            try {
                const entry = await this.controller.get(this.body.dn);
                if (this.opened === opened && this.panel.isOpen) {
                    this.show(entry, false);
                }
            } catch (error) {
                // Only an entry which is gone closes the panel, and it's
                // otherwise kept, until it can be loaded
                if (this.opened === opened && this.panel.isOpen) {
                    if (error instanceof ApiError && error.status === 404) {
                        this.panel.close();
                    } else {
                        this.notifications?.error(`${rdn(this.body.dn)} couldn't be loaded again`, error);
                    }
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

    // openEntry loads an entry, such as the selected branch, with its
    // attributes, and shows it
    private async openEntry(dn: string) {
        if (!this.controller) {
            return;
        }
        this.leaves.close();
        this.opened++;
        const opened = this.opened;
        const entry = await this.controller.get(dn);
        if (this.opened === opened) {
            this.show(entry, true);
        }
    }

    // show shows an entry's attributes, and what can be done with it
    private show(entry: LdapObject, open: boolean) {
        this.body = { dn: entry.dn, content: attrsView(entry) };
        this.panel.setHeader({ title: rdn(entry.dn), subtitle: classesOf(entry).join(', ') || 'Entry' });
        // The entries with the next user and group IDs aren't deleted
        const base = this.current?.base_dn;
        const actions: PanelAction[] = base && isCounter(entry.dn, base) ? [] : [
            { label: 'Delete', kind: 'danger', close: false, run: () => this.delete(entry) },
        ];
        this.panel.setActions(actions);
        if (open) {
            this.opened++;
            this.panel.open({ dn: entry.dn });
        }
    }

    // delete deletes an entry, which has no children, once it's confirmed,
    // and loads its parent's children again. A branch which is deleted
    // isn't selected.
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
        if (this.branch && sameDN(this.branch, entry.dn)) {
            this.selectBranch(parent);
        }
        if (this.loaded.has(dnKey(parent))) {
            await this.load(parent);
            await this.leaves.refresh();
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

// classesOf returns an entry's object classes, other than top
function classesOf(entry: LdapObject): string[] {
    return values(entry, 'objectClass').filter((v): v is string => typeof v === 'string' && v.toLowerCase() !== 'top');
}

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
