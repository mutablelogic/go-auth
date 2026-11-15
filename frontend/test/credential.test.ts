import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ApiError, type Client } from '@mutablelogic/go-server/api';
import { credentialChange, credentialForm, credentialFormErrors, credentialRequest } from '../src/credential/form.ts';
import { sortCredentials } from '../src/credential/controller.ts';
import * as api from '../src/credential/httpclient.ts';

// fakeClient returns a client whose fetch records each request, and
// returns the response of the function
function fakeClient(respond: (method: string, path: string, init: RequestInit) => Response) {
    const requests: { method: string; path: string; init: RequestInit }[] = [];
    const client: Client = {
        base: 'http://localhost/api',
        fetch: (async (input: RequestInfo | URL, init: RequestInit = {}) => {
            const path = new URL(String(input)).pathname;
            const method = init.method ?? 'GET';
            requests.push({ method, path, init });
            return respond(method, path, init);
        }) as typeof fetch,
    };
    return { client, requests };
}

const json = (status: number, body?: unknown) => new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
});

test('credentialForm', async (t) => {
    await t.test('a new credential needs a key and a value', () => {
        const form = credentialForm();
        assert.equal(form.replace, false);
        assert.deepEqual(Object.keys(credentialFormErrors(form)).sort(), ['key', 'value']);
    });

    await t.test('the key is an identifier', () => {
        for (const key of ['1abc', 'a b', 'a/b', '.hidden', 'x'.repeat(65)]) {
            assert.ok(credentialFormErrors({ ...credentialForm(), key, value: 'v', confirm: 'v' }).key, key);
        }
        assert.deepEqual(credentialFormErrors({ ...credentialForm(), key: ' token-1_a ', value: 'v', confirm: 'v' }), {});
    });

    await t.test('a value is text, or JSON when json is set', () => {
        const text = { ...credentialForm({ key: 'token' }), value: 'hunter2', confirm: 'hunter2' };
        assert.equal(text.replace, true);
        assert.deepEqual(credentialRequest(text), { key: 'token', credentials: 'hunter2', description: '' });

        const object = { ...credentialForm({ key: 'login' }), value: '{"user":"admin"}', json: true };
        assert.deepEqual(credentialFormErrors(object), {});
        assert.deepEqual(credentialRequest(object), { key: 'login', credentials: { user: 'admin' }, description: '' });

        assert.ok(credentialFormErrors({ ...object, value: '{user' }).value);
    });

    await t.test('replacing keeps the description, which can be changed', () => {
        const form = credentialForm({ key: 'token', description: 'The API token' });
        assert.equal(form.description, 'The API token');
        assert.equal(credentialRequest({ ...form, value: 'v' }).description, 'The API token');
        assert.equal(credentialRequest({ ...form, value: 'v', description: '  ' }).description, '', 'an empty one removes it');
    });

    await t.test('a text value is typed twice, and JSON once', () => {
        const form = { ...credentialForm(), key: 'token', value: 'hunter2' };
        assert.ok(credentialFormErrors(form).confirm, 'not typed again');
        assert.ok(credentialFormErrors({ ...form, confirm: 'hunter3' }).confirm, 'not the same');
        assert.deepEqual(credentialFormErrors({ ...form, confirm: 'hunter2' }), {});
        assert.deepEqual(credentialFormErrors({ ...form, value: '{"a":1}', json: true }), {}, 'JSON is typed once');
    });

    await t.test('editing changes the value, the description alone, or nothing', () => {
        const form = credentialForm({ key: 'token', description: 'The API token' });
        assert.deepEqual(credentialFormErrors(form), {}, 'an empty value is kept');
        assert.equal(credentialChange(form), 'none');
        assert.equal(credentialChange({ ...form, description: ' The API token ' }), 'none');
        assert.equal(credentialChange({ ...form, description: 'Changed' }), 'description');
        assert.equal(credentialChange({ ...form, description: '' }), 'description', 'removing it is a change');
        assert.equal(credentialChange({ ...form, value: 'v', confirm: 'v' }), 'value');
        assert.ok(credentialFormErrors({ ...form, confirm: 'x' }).confirm, 'the value again, without the value');
        assert.equal(credentialChange({ ...credentialForm(), key: 'new', value: '' }), 'none');
    });
});

test('sortCredentials', () => {
    const credentials = [
        { key: 'b', updated_at: '2026-01-02T00:00:00Z' },
        { key: 'c' },
        { key: 'a', updated_at: '2026-01-03T00:00:00Z' },
    ];
    const keys = (sorted: { key: string }[]) => sorted.map((c) => c.key);
    assert.deepEqual(keys(sortCredentials(credentials)), ['a', 'b', 'c']);
    assert.deepEqual(keys(sortCredentials(credentials, { key: 'key', direction: 'descending' })), ['c', 'b', 'a']);
    assert.deepEqual(keys(sortCredentials(credentials, { key: 'updated_at', direction: 'ascending' })), ['b', 'a', 'c'], 'without a time is last');
    assert.deepEqual(keys(sortCredentials(credentials, { key: 'updated_at', direction: 'descending' })), ['a', 'b', 'c']);
    assert.equal(credentials[0].key, 'b', "the credentials aren't sorted in place");
});

test('httpclient', async (t) => {
    await t.test('lists, gets, stores and deletes', async () => {
        const { client, requests } = fakeClient((method, path) => {
            if (method === 'GET' && path === '/api/credential') return json(200, { count: 1, body: [{ key: 'token' }] });
            if (method === 'GET') return json(200, { key: 'token', updated_at: '2026-01-01T00:00:00Z' });
            if (method === 'PUT') return json(200, { key: 'token' });
            return new Response(null, { status: 204 });
        });
        assert.deepEqual(await api.listCredentials(client), { count: 1, body: [{ key: 'token' }] });
        assert.equal((await api.getCredentialMeta(client, 'token')).updated_at, '2026-01-01T00:00:00Z');
        assert.deepEqual(await api.setCredential(client, { key: 'token', credentials: 'x' }), { key: 'token' });
        await api.deleteCredential(client, 'token');
        assert.deepEqual(requests.map((r) => `${r.method} ${r.path}`), [
            'GET /api/credential',
            'GET /api/credential/token',
            'PUT /api/credential',
            'DELETE /api/credential/token',
        ]);
        assert.deepEqual(JSON.parse(String(requests[2].init.body)), { key: 'token', credentials: 'x' });
    });

    await t.test("gets a value with the passphrase, as text, which isn't cached", async () => {
        const { client, requests } = fakeClient(() => json(200, { user: 'admin' }));
        assert.deepEqual(await api.getCredential(client, 'login', 'my passphrase'), { user: 'admin' });
        assert.equal(requests[0].method, 'POST');
        assert.equal(requests[0].path, '/api/credential/login');
        assert.equal(requests[0].init.body, 'my passphrase');
        assert.equal((requests[0].init.headers as Record<string, string>)['Content-Type'], 'text/plain');
        assert.equal(requests[0].init.cache, 'no-store');
    });

    await t.test('a wrong passphrase is an ApiError', async () => {
        const { client } = fakeClient(() => json(403, { code: 403, reason: 'Forbidden: invalid passphrase' }));
        await assert.rejects(api.getCredential(client, 'login', 'wrong'), (error: unknown) => error instanceof ApiError && error.status === 403);
    });

    await t.test('rotating returns false when it already uses the latest passphrase', async () => {
        let status = 204;
        const { client } = fakeClient(() => new Response(null, { status }));
        assert.equal(await api.rotateCredential(client, 'token'), true);
        status = 304;
        assert.equal(await api.rotateCredential(client, 'token'), false);
        status = 404;
        await assert.rejects(api.rotateCredential(client, 'token'), ApiError);
    });

    await t.test('changes a description, without the value', async () => {
        const { client, requests } = fakeClient(() => json(200, { key: 'token', description: 'Changed' }));
        assert.deepEqual(await api.describeCredential(client, 'token', 'Changed'), { key: 'token', description: 'Changed' });
        assert.equal(requests[0].method, 'PATCH');
        assert.equal(requests[0].path, '/api/credential/token');
        assert.deepEqual(JSON.parse(String(requests[0].init.body)), { description: 'Changed' });
    });

    await t.test('keys are escaped in paths', async () => {
        const { client, requests } = fakeClient(() => new Response(null, { status: 204 }));
        await api.deleteCredential(client, 'a/b');
        assert.equal(requests[0].path, '/api/credential/a%2Fb');
    });
});
