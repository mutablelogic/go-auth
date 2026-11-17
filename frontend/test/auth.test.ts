import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ApiError, type Client } from '@mutablelogic/go-server/api';
import { getSession, localPath, redirectURL, signIn, signInURL, signOut } from '../src/auth/index.ts';

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

test('localPath', () => {
    // A path on this server, with its query and hash
    for (const path of ['/', '/api/auth/authorize?client_id=x&state=y', '/#credentials']) {
        assert.equal(localPath(path), path);
    }
    // Not another site's, or nothing
    for (const path of [null, undefined, '', 'https://evil.example.com/', '//evil.example.com/', '/\\evil.example.com', 'relative', '/a\nb', 'javascript:alert(1)']) {
        assert.equal(localPath(path), '/', String(path));
    }
});

test('signInURL', () => {
    assert.equal(signInURL('/api/auth/authorize?a=1&b=2'), '/login.html?return=%2Fapi%2Fauth%2Fauthorize%3Fa%3D1%26b%3D2');
    assert.equal(signInURL('https://evil.example.com/'), '/login.html?return=%2F');
});

test('redirectURL', () => {
    const { client } = fakeClient(() => json(200));
    const u = new URL(redirectURL(client, 'google', '/#ldap'));
    assert.equal(u.pathname, '/api/auth/google/login');
    assert.equal(u.searchParams.get('return'), '/#ldap');
});

test('signIn, getSession and signOut', async () => {
    const session = { id: 's', user: { id: 'u', name: 'Alice' }, provider: 'ldap', created_at: '', expires_at: '' };
    const { client, requests } = fakeClient((method, path, init) => {
        if (method === 'POST' && path === '/api/auth/ldap/login') {
            const body = JSON.parse(String(init.body));
            return body.password === 'secret' ? json(200, session) : json(401, { code: 401, reason: "The username or password isn't right" });
        }
        if (method === 'GET' && path === '/api/auth/session') {
            return json(200, session);
        }
        if (method === 'POST' && path === '/api/auth/logout') {
            return new Response(null, { status: 204 });
        }
        return json(404);
    });
    assert.deepEqual(await signIn(client, 'ldap', 'alice', 'secret'), session);
    await assert.rejects(signIn(client, 'ldap', 'alice', 'wrong'), (error: unknown) => error instanceof ApiError && error.status === 401);
    assert.deepEqual(await getSession(client), session);
    await signOut(client);
    assert.deepEqual(requests.map((r) => `${r.method} ${r.path}`), [
        'POST /api/auth/ldap/login',
        'POST /api/auth/ldap/login',
        'GET /api/auth/session',
        'POST /api/auth/logout',
    ]);
});
