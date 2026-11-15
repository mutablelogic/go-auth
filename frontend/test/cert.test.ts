import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { Client } from '@mutablelogic/go-server/api';
import { certForm, certFormErrors, certRequest, renewForm, renewFormErrors, renewRequest, splitList, tagsError, tagsRequest } from '../src/cert/form.ts';
import { certificatePEM, pem, privateKeyPEM } from '../src/cert/pem.ts';
import { Day, RootCertName, certExpired, certType } from '../src/cert/schema.ts';
import * as api from '../src/cert/httpclient.ts';

// fakeClient returns a client whose fetch records each request, and
// returns the response of the function
function fakeClient(respond: (method: string, url: URL, init: RequestInit) => Response) {
    const requests: { method: string; url: URL; body?: unknown }[] = [];
    const client: Client = {
        base: 'http://localhost/api',
        fetch: (async (input: RequestInfo | URL, init: RequestInit = {}) => {
            const url = new URL(String(input));
            const method = init.method ?? 'GET';
            requests.push({ method, url, body: init.body ? JSON.parse(String(init.body)) : undefined });
            return respond(method, url, init);
        }) as typeof fetch,
    };
    return { client, requests };
}

const json = (status: number, body?: unknown) => new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
});

test('certForm', async (t) => {
    await t.test('a certificate needs a name and a certificate authority', () => {
        assert.deepEqual(Object.keys(certFormErrors(certForm(false))).sort(), ['name', 'signer']);
        assert.deepEqual(Object.keys(certFormErrors(certForm(true))), ['name'], "a CA doesn't need a signer");
    });

    await t.test('names and tags are identifiers', () => {
        for (const name of ['1abc', 'a b', 'a.b', 'x'.repeat(65)]) {
            assert.ok(certFormErrors({ ...certForm(true), name }).name, name);
        }
        assert.ok(certFormErrors({ ...certForm(true), name: 'ca', tags: 'prod, bad tag!' }).tags);
        assert.equal(tagsError('a, b c'), undefined);
        assert.ok(tagsError('1a'));
    });

    await t.test('the expiry is a number of days', () => {
        for (const expiry of ['x', '-1', '0', '1.5']) {
            assert.ok(certFormErrors({ ...certForm(true), name: 'ca', expiry }).expiry, expiry);
        }
        assert.equal(certRequest({ ...certForm(true), name: 'ca', expiry: '30' }).expiry, 30 * Day);
        assert.equal(certRequest({ ...certForm(true), name: 'ca' }).expiry, undefined, "the server's default");
    });

    await t.test('a certificate has SAN entries, and a CA does not', () => {
        const req = certRequest({ ...certForm(false, 'ca'), name: ' web ', san: 'web.example.test,\n10.0.0.1  web.example.test', tags: 'a, b, a' });
        assert.deepEqual(req, { name: 'web', san: ['web.example.test', '10.0.0.1'], tags: ['a', 'b'] });
        assert.ok(certFormErrors({ ...certForm(true), name: 'ca', san: 'x.example.test' }).san);
    });

    await t.test('only the subject fields which are set are sent', () => {
        const req = certRequest({ ...certForm(true), name: 'ca', subject: { organizationName: ' Example ', countryName: '' } });
        assert.deepEqual(req.subject, { organizationName: 'Example' });
    });

    await t.test('renewing keeps what is not set', () => {
        assert.deepEqual(renewRequest(renewForm()), {});
        assert.deepEqual(renewRequest({ expiry: '7', subject: { localityName: 'London' } }), { expiry: 7 * Day, subject: { localityName: 'London' } });
        assert.ok(renewFormErrors({ expiry: 'soon', subject: {} }).expiry);
    });

    await t.test('tags', () => {
        assert.deepEqual(splitList(' a,b\nc  a '), ['a', 'b', 'c']);
        assert.deepEqual(tagsRequest(''), { tags: [] }, 'none removes them');
    });
});

test('pem', () => {
    const base64 = 'A'.repeat(100);
    assert.equal(pem('CERTIFICATE', base64), `-----BEGIN CERTIFICATE-----\n${'A'.repeat(64)}\n${'A'.repeat(36)}\n-----END CERTIFICATE-----\n`);

    // A certificate, then its issuers
    const bundle = { name: 'web', serial: '1', cert: 'Y2VydA==', chain: [{ name: 'ca', serial: '1', cert: 'Y2E=' }, { name: RootCertName, serial: '1', cert: 'cm9vdA==' }] };
    const chain = certificatePEM(bundle);
    assert.equal(chain.match(/BEGIN CERTIFICATE/g)?.length, 3);
    assert.ok(chain.indexOf('Y2VydA==') < chain.indexOf('cm9vdA=='));

    assert.match(privateKeyPEM({ ...bundle, key: 'a2V5' }), /^-----BEGIN PRIVATE KEY-----\na2V5\n/);
    assert.throws(() => privateKeyPEM(bundle));
});

test('schema', () => {
    assert.equal(certType({ name: RootCertName, serial: '1', is_ca: true }), 'root');
    assert.equal(certType({ name: 'ca', serial: '1', is_ca: true }), 'ca');
    assert.equal(certType({ name: 'web', serial: '1' }), 'certificate');
    assert.equal(certExpired({ name: 'web', serial: '1', not_after: '2000-01-01T00:00:00Z' }), true);
    assert.equal(certExpired({ name: 'web', serial: '1', not_after: '2999-01-01T00:00:00Z' }), false);
});

test('httpclient', async (t) => {
    await t.test('paths, of a version, or the latest', () => {
        assert.equal(api.keyPath('cert', { name: 'web' }), 'cert/web');
        assert.equal(api.keyPath('cert', { name: 'web', serial: '12' }, 'key'), 'cert/web/12/key');
        assert.equal(api.keyPath('ca', { name: 'my ca' }, 'renew'), 'ca/my%20ca/renew');
    });

    await t.test('requests', async () => {
        const { client, requests } = fakeClient((method, url) => method === 'GET' && url.pathname === '/api/cert'
            ? json(200, { count: 0 })
            : json(method === 'PATCH' || method === 'GET' ? 200 : 201, { name: 'web', serial: '1' }));

        await api.listCerts(client, { offset: 10, limit: 5, is_ca: true, tags: ['prod'] });
        await api.getCert(client, { name: 'web' }, true);
        await api.getPrivateKey(client, { name: 'web', serial: '1' });
        await api.createCA(client, { name: 'ca' });
        await api.renewCA(client, { name: 'ca', serial: '2' }, { expiry: Day });
        await api.createCert(client, { name: 'web', san: ['web.example.test'] }, { name: 'ca' });
        await api.renewCert(client, { name: 'web' });
        await api.updateCert(client, { name: 'web', serial: '1' }, { enabled: false });

        assert.deepEqual(requests.map((r) => `${r.method} ${r.url.pathname}${r.url.search}`), [
            'GET /api/cert?offset=10&limit=5&is_ca=true&tags=prod',
            'GET /api/cert/web?chain=true',
            'GET /api/cert/web/1/key',
            'POST /api/ca',
            'POST /api/ca/ca/2/renew',
            'POST /api/cert/ca',
            'POST /api/cert/web/renew',
            'PATCH /api/cert/web/1',
        ]);
        assert.deepEqual(requests[4].body, { expiry: Day });
        assert.deepEqual(requests[5].body, { name: 'web', san: ['web.example.test'] });
        assert.deepEqual(requests[7].body, { enabled: false });
    });
});
