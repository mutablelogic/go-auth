// The client of the credential API, which go-auth's credential/httphandler
// serves, at the client's prefix, such as /api

import { ApiError, errorResponse, request, url, type Client } from '@mutablelogic/go-server/api';
import type { Credential, CredentialList, CredentialSet } from './schema.ts';

// listCredentials returns the stored credentials, in key order, without
// their values
export async function listCredentials(client: Client, signal?: AbortSignal): Promise<CredentialList> {
    return request<CredentialList>(client, 'GET', 'credential', { signal });
}

// getCredentialMeta returns a stored credential's key, and when it was last
// changed, without its value
export async function getCredentialMeta(client: Client, key: string): Promise<Credential> {
    return request<Credential>(client, 'GET', `credential/${encodeURIComponent(key)}`);
}

// setCredential stores the credential, replacing any with the key
export async function setCredential(client: Client, credential: CredentialSet): Promise<Credential> {
    return request<Credential>(client, 'PUT', 'credential', { body: credential });
}

// getCredential returns a credential's value, with the passphrase it was
// encrypted with, which is sent as text, and never cached. Only the
// backends which encrypt with their own passphrases return values.
export async function getCredential(client: Client, key: string, passphrase: string): Promise<unknown> {
    const response = await (client.fetch ?? fetch)(url(client.base, `credential/${encodeURIComponent(key)}`), {
        method: 'POST',
        headers: { 'Accept': 'application/json', 'Content-Type': 'text/plain' },
        body: passphrase,
        cache: 'no-store',
    });
    if (!response.ok) {
        throw await errorResponse(response);
    }
    const text = await response.text();
    if (!text) {
        throw new ApiError(response.status, 'the credential has no value');
    }
    return JSON.parse(text);
}

// describeCredential changes a stored credential's description, without its
// value, or removes it, when it's empty
export async function describeCredential(client: Client, key: string, description: string): Promise<Credential> {
    return request<Credential>(client, 'PATCH', `credential/${encodeURIComponent(key)}`, { body: { description } });
}

// deleteCredential deletes a stored credential
export async function deleteCredential(client: Client, key: string): Promise<void> {
    await request<void>(client, 'DELETE', `credential/${encodeURIComponent(key)}`);
}

// rotateCredential re-encrypts a credential with the latest passphrase
// version, and returns false when it already uses it
export async function rotateCredential(client: Client, key: string): Promise<boolean> {
    try {
        await request<void>(client, 'POST', `credential/${encodeURIComponent(key)}/rotate`);
        return true;
    } catch (error) {
        if (error instanceof ApiError && error.status === 304) {
            return false;
        }
        throw error;
    }
}
