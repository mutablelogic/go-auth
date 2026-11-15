// CertController keeps the certificates, a page at a time, in a
// ListController, which a gs-table shows, and creates, renews and changes
// them, loading the list again when they change. The server pages them, in
// name order, with the latest version of each name first.

import type { Client } from '@mutablelogic/go-server/api';
import type { ChangesController } from '@mutablelogic/go-server/broadcaster';
import { ListController } from '@mutablelogic/go-server/list';
import type { NotificationController } from '@mutablelogic/go-server/notification';
import * as api from './httpclient.ts';
import type { CertBundle, CertKey, CertMeta, Certificate, CreateCertRequest, RenewCertRequest } from './schema.ts';

// CertOptions are the controller's notifications, which say why the
// certificates can't be loaded, and its changes, which load them again
export interface CertOptions {
    notifications?: NotificationController;
    changes?: ChangesController;
    pageSize?: number;
}

export class CertController {
    readonly client: Client;
    readonly list: ListController<Certificate>;

    constructor(client: Client, options: CertOptions = {}) {
        this.client = client;
        this.list = new ListController<Certificate>({
            name: 'Certificates',
            list: async (offset, limit) => {
                const page = await api.listCerts(client, { offset, limit });
                return { count: page.count, body: page.body ?? [] };
            },
            get: (cert) => api.getCert(client, cert).catch(() => cert),
            same: (a, b) => a.name === b.name && a.serial === b.serial,
            notifications: options.notifications,
            changes: options.changes,
            filter: options.changes ? { table: 'cert' } : undefined,
            pageSize: options.pageSize,
        });
    }

    // authorities returns the enabled certificate authorities' names, which
    // can sign certificates, each once, as their latest version signs
    async authorities(): Promise<string[]> {
        const names = new Set<string>();
        for (let offset = 0; ; ) {
            const page = await api.listCerts(this.client, { offset, limit: 100, is_ca: true, enabled: true });
            for (const cert of page.body ?? []) {
                names.add(cert.name);
            }
            offset += page.body?.length ?? 0;
            if (!page.body?.length || offset >= page.count) {
                return [...names];
            }
        }
    }

    // create creates a certificate authority, or a certificate signed by the
    // latest version of the certificate authority, and loads the list again
    async create(req: CreateCertRequest, signer?: string): Promise<Certificate> {
        const created = signer ? await api.createCert(this.client, req, { name: signer }) : await api.createCA(this.client, req);
        await this.list.refresh();
        return created;
    }

    // renew renews a version of a certificate authority, or a certificate,
    // and loads the list again
    async renew(cert: Certificate, req: RenewCertRequest = {}): Promise<Certificate> {
        const key = { name: cert.name, serial: cert.serial };
        const renewed = cert.is_ca ? await api.renewCA(this.client, key, req) : await api.renewCert(this.client, key, req);
        await this.list.refresh();
        return renewed;
    }

    // update enables or disables a version of a certificate, or changes its
    // tags, and loads the list again
    async update(key: CertKey, meta: CertMeta): Promise<Certificate> {
        const updated = await api.updateCert(this.client, key, meta);
        await this.list.refresh();
        return updated;
    }

    // bundle returns a version of a certificate, with its issuers
    bundle(key: CertKey): Promise<CertBundle> {
        return api.getCert(this.client, key, true);
    }

    // privateKey returns a version of a leaf certificate, with its private
    // key
    privateKey(key: CertKey): Promise<CertBundle> {
        return api.getPrivateKey(this.client, key);
    }
}
