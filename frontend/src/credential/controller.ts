// CredentialController keeps the stored credentials, a page at a time, in
// a ListController, which a gs-table shows, and stores, deletes and
// rotates them, loading the list again when they change

import type { Client } from '@mutablelogic/go-server/api';
import type { ChangesController } from '@mutablelogic/go-server/broadcaster';
import { ListController, type Sort } from '@mutablelogic/go-server/list';
import type { NotificationController } from '@mutablelogic/go-server/notification';
import * as api from './httpclient.ts';
import type { Credential, CredentialSet } from './schema.ts';

// CredentialOptions are the controller's notifications, which say why the
// credentials can't be loaded, and its changes, which load them again
export interface CredentialOptions {
    notifications?: NotificationController;
    changes?: ChangesController;
    pageSize?: number;
}

// CredentialSort is what the credentials can be sorted by
export type CredentialSort = 'key' | 'updated_at';

export class CredentialController {
    readonly client: Client;
    readonly list: ListController<Credential>;

    // rotations is how many credentials need rotating, of all of them, when
    // the list was last loaded
    rotations = 0;

    constructor(client: Client, options: CredentialOptions = {}) {
        this.client = client;
        this.list = new ListController<Credential>({
            name: 'Credentials',
            // The API returns every credential, which are sorted and paged
            // here
            list: async (offset, limit, sort) => {
                const all = sortCredentials((await api.listCredentials(client)).body ?? [], sort);
                this.rotations = all.filter((credential) => credential.rotate).length;
                return { count: all.length, body: all.slice(offset, offset + limit) };
            },
            get: (credential) => api.getCredentialMeta(client, credential.key),
            same: (a, b) => a.key === b.key,
            notifications: options.notifications,
            changes: options.changes,
            filter: options.changes ? { table: 'credential' } : undefined,
            pageSize: options.pageSize,
            sort: { key: 'key', direction: 'ascending' },
        });
    }

    // set stores the credential, and loads the list again
    async set(credential: CredentialSet): Promise<Credential> {
        const stored = await api.setCredential(this.client, credential);
        await this.list.refresh();
        return stored;
    }

    // describe changes a credential's description, without its value, and
    // loads the list again
    async describe(key: string, description: string): Promise<Credential> {
        const described = await api.describeCredential(this.client, key, description);
        await this.list.refresh();
        return described;
    }

    // value returns a credential's value, with its passphrase
    value(key: string, passphrase: string): Promise<unknown> {
        return api.getCredential(this.client, key, passphrase);
    }

    // delete deletes the credential, closes it, when it's open, and loads
    // the list again
    async delete(key: string): Promise<void> {
        await api.deleteCredential(this.client, key);
        if (this.list.current.selected?.key === key) {
            this.list.close();
        }
        await this.list.refresh();
    }

    // rotate re-encrypts the credential with the latest passphrase version,
    // and returns false when it already uses it
    async rotate(key: string): Promise<boolean> {
        const rotated = await api.rotateCredential(this.client, key);
        if (rotated) {
            await this.list.refresh();
        }
        return rotated;
    }

    // rotateAll rotates each credential which needs rotating, of all of
    // them, and loads the list again, and returns how many were rotated
    async rotateAll(): Promise<number> {
        const all = (await api.listCredentials(this.client)).body ?? [];
        let rotated = 0;
        for (const credential of all.filter((c) => c.rotate)) {
            if (await api.rotateCredential(this.client, credential.key)) {
                rotated++;
            }
        }
        await this.list.refresh();
        return rotated;
    }
}

// sortCredentials returns the credentials sorted by their keys, or when
// they were last changed, which those without a time come after
export function sortCredentials(credentials: readonly Credential[], sort?: Sort): Credential[] {
    const direction = sort?.direction === 'descending' ? -1 : 1;
    const byKey = (a: Credential, b: Credential) => a.key.localeCompare(b.key);
    return [...credentials].sort((a, b) => {
        if (sort?.key === 'updated_at') {
            const at = a.updated_at ? Date.parse(a.updated_at) : NaN;
            const bt = b.updated_at ? Date.parse(b.updated_at) : NaN;
            if (Number.isNaN(at) !== Number.isNaN(bt)) {
                return Number.isNaN(at) ? 1 : -1;
            }
            if (at !== bt && !Number.isNaN(at)) {
                return (at - bt) * direction;
            }
            return byKey(a, b);
        }
        return byKey(a, b) * direction;
    });
}
