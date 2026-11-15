// The client of the certificate API, which go-auth's cert/httphandler
// serves, at the client's prefix, such as /api. A key without a serial is a
// certificate's latest version.

import { request, type Client } from '@mutablelogic/go-server/api';
import type { CertBundle, CertKey, CertList, CertListRequest, CertMeta, Certificate, CreateCertRequest, RenewCertRequest } from './schema.ts';

// listCerts returns a page of certificates, other than the root, without
// their private keys
export async function listCerts(client: Client, req: CertListRequest = {}, signal?: AbortSignal): Promise<CertList> {
    // The query is in the path, as it repeats tags, each of which is
    // required, which the request's query can't
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(req)) {
        if (key === 'tags') {
            for (const tag of (value as string[] | undefined) ?? []) {
                params.append('tags', tag);
            }
        } else if (value !== undefined) {
            params.set(key, String(value));
        }
    }
    const search = params.toString();
    return request<CertList>(client, 'GET', search ? `cert?${search}` : 'cert', { signal });
}

// getCert returns a version of a certificate, with its issuers, up to the
// root, when chain is true. A disabled certificate is a conflict.
export async function getCert(client: Client, key: Partial<CertKey> & { name: string }, chain = false): Promise<CertBundle> {
    return request<CertBundle>(client, 'GET', keyPath('cert', key), { query: chain ? { chain: true } : undefined });
}

// getPrivateKey returns a version of a leaf certificate with its private
// key, and its issuers when chain is true. A certificate authority's key is
// never returned.
export async function getPrivateKey(client: Client, key: Partial<CertKey> & { name: string }, chain = false): Promise<CertBundle> {
    return request<CertBundle>(client, 'GET', keyPath('cert', key, 'key'), { query: chain ? { chain: true } : undefined });
}

// createCA creates a certificate authority, signed by the root
export async function createCA(client: Client, req: CreateCertRequest): Promise<Certificate> {
    return request<Certificate>(client, 'POST', 'ca', { body: req });
}

// renewCA renews a version of a certificate authority. The current version
// stays enabled, so its certificates still work.
export async function renewCA(client: Client, key: Partial<CertKey> & { name: string }, req: RenewCertRequest = {}): Promise<Certificate> {
    return request<Certificate>(client, 'POST', keyPath('ca', key, 'renew'), { body: req });
}

// createCert creates a leaf certificate, signed by a version of a
// certificate authority
export async function createCert(client: Client, req: CreateCertRequest, ca: Partial<CertKey> & { name: string }): Promise<Certificate> {
    return request<Certificate>(client, 'POST', keyPath('cert', ca), { body: req });
}

// renewCert renews a version of a leaf certificate, which disables it
export async function renewCert(client: Client, key: Partial<CertKey> & { name: string }, req: RenewCertRequest = {}): Promise<Certificate> {
    return request<Certificate>(client, 'POST', keyPath('cert', key, 'renew'), { body: req });
}

// updateCert enables or disables a version of a certificate, or changes its
// tags
export async function updateCert(client: Client, key: Partial<CertKey> & { name: string }, meta: CertMeta): Promise<Certificate> {
    return request<Certificate>(client, 'PATCH', keyPath('cert', key), { body: meta });
}

// keyPath is the path of a certificate's version, or its latest version,
// without a serial, then the rest of the path
export function keyPath(prefix: string, key: Partial<CertKey> & { name: string }, ...rest: string[]): string {
    const path = [prefix, encodeURIComponent(key.name)];
    if (key.serial) {
        path.push(encodeURIComponent(key.serial));
    }
    return [...path, ...rest].join('/');
}
