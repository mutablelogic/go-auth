// CertController keeps the certificates, or only the certificate
// authorities, or leaf certificates, a page at a time, in a
// ListController, which a gs-table shows, and creates, renews and changes
// them, loading the list again when they change. The server pages them, in
// name order, with the latest version of each name first.

import type { Client } from '@mutablelogic/go-server/api';
import type { ChangesController } from '@mutablelogic/go-server/broadcaster';
import { ListController } from '@mutablelogic/go-server/list';
import type { NotificationController } from '@mutablelogic/go-server/notification';
import * as api from './httpclient.ts';
import type { CertBundle, CertKey, CertMeta, Certificate, CreateCertRequest, RenewCertRequest, Subject, SubjectMeta } from './schema.ts';

// CertOptions are the controller's notifications, which say why the
// certificates can't be loaded, and its changes, which load them again
export interface CertOptions {
    notifications?: NotificationController;
    changes?: ChangesController;
    pageSize?: number;
    // ca lists only certificate authorities, when it's true, or only leaf
    // certificates, when it's false, or both when it's not set
    ca?: boolean;
}

export class CertController {
    readonly client: Client;
    readonly list: ListController<Certificate>;

    constructor(client: Client, options: CertOptions = {}) {
        this.client = client;
        this.list = new ListController<Certificate>({
            name: 'Certificates',
            list: async (offset, limit) => {
                // Only each certificate's latest version, which is renewed,
                // and signs certificates, and whose older versions are listed
                // with versions
                const page = await api.listCerts(client, { offset, limit, is_ca: options.ca, latest: true });
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

    // authorities returns the names of the certificate authorities whose
    // latest version is enabled, which signs certificates
    async authorities(): Promise<string[]> {
        const names: string[] = [];
        for (let offset = 0; ; ) {
            const page = await api.listCerts(this.client, { offset, limit: 100, is_ca: true, latest: true });
            names.push(...(page.body ?? []).filter((cert) => cert.enabled ?? true).map((cert) => cert.name));
            offset += page.body?.length ?? 0;
            if (!page.body?.length || offset >= page.count) {
                return names;
            }
        }
    }

    // versions returns the older versions of a certificate, the latest first,
    // which aren't renewed, and don't sign certificates
    async versions(name: string): Promise<Certificate[]> {
        const versions: Certificate[] = [];
        for (let offset = 0; ; ) {
            const page = await api.listCerts(this.client, { offset, limit: 100, name, latest: false });
            versions.push(...(page.body ?? []));
            offset += page.body?.length ?? 0;
            if (!page.body?.length || offset >= page.count) {
                return versions;
            }
        }
    }

    // setEnabled enables or disables the certificates, and loads the list
    // again, once
    async setEnabled(certs: readonly CertKey[], enabled: boolean): Promise<void> {
        for (const cert of certs) {
            await api.updateCert(this.client, cert, { enabled });
        }
        await this.list.refresh();
    }

    // subjects returns the stored subjects which have fields, which a
    // certificate can be created with, in the order they were created
    async subjects(): Promise<Subject[]> {
        const subjects: Subject[] = [];
        for (let offset = 0; ; ) {
            const page = await api.listSubjects(this.client, offset, 100);
            subjects.push(...(page.body ?? []).filter((subject) => subject.subject));
            offset += page.body?.length ?? 0;
            if (!page.body?.length || offset >= page.count) {
                return subjects;
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

        // The selection is the update, before the list is loaded again, as a
        // disabled certificate can't be got again, so would stay as it was
        const selected = this.list.current.selected;
        if (selected && selected.name === updated.name && selected.serial === updated.serial) {
            this.list.open(updated);
        }
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

// SubjectController keeps the subjects, a page at a time, in a
// ListController, which a gs-table shows, and creates, updates and deletes
// them, loading the list again when they change, or certificates do, which
// changes how many use each
export class SubjectController {
    readonly client: Client;
    readonly list: ListController<Subject>;

    constructor(client: Client, options: Omit<CertOptions, 'ca'> = {}) {
        this.client = client;
        this.list = new ListController<Subject>({
            name: 'Subjects',
            list: async (offset, limit) => {
                const page = await api.listSubjects(client, offset, limit);
                return { count: page.count, body: page.body ?? [] };
            },
            get: (subject) => api.getSubject(client, subject.id),
            same: (a, b) => a.id === b.id,
            notifications: options.notifications,
            changes: options.changes,
            filter: options.changes ? [{ table: 'subject' }, { table: 'cert' }] : undefined,
            pageSize: options.pageSize,
        });
    }

    // create creates a subject, or returns an identical one, and loads the
    // list again
    async create(meta: SubjectMeta): Promise<Subject> {
        const created = await api.createSubject(this.client, meta);
        await this.list.refresh();
        return created;
    }

    // update updates a subject which no certificate uses, and loads the list
    // again
    async update(id: number, meta: SubjectMeta): Promise<Subject> {
        const updated = await api.updateSubject(this.client, id, meta);
        await this.list.refresh();
        return updated;
    }

    // delete deletes a subject which no certificate uses, closes it, when
    // it's open, and loads the list again
    async delete(id: number): Promise<void> {
        await api.deleteSubject(this.client, id);
        if (this.list.current.selected?.id === id) {
            this.list.close();
        }
        await this.list.refresh();
    }
}
