import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { Client } from '@mutablelogic/go-server/api';
import { certForm, certFormErrors, certRequest, validSAN, renewForm, renewFormErrors, renewRequest, splitList, subjectCreateRequest, subjectUpdateRequest, tagsError, tagsRequest } from '../src/cert/form.ts';
import { certificatePEM, pem, privateKeyPEM } from '../src/cert/pem.ts';
import { Day, RootCertName, certExpired, certType, certValidity } from '../src/cert/schema.ts';
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

    await t.test('a stored subject is sent as it is, which removes the signer\'s other fields', () => {
        const subjects = [{ id: 3, certs: 0, organizationName: 'Stored Org', countryName: 'GB', subject: 'O=Stored Org,C=GB' }];
        const req = certRequest({ ...certForm(false, 'ca'), name: 'web', subjectId: 3 }, subjects);
        assert.deepEqual(req.subject, {
            organizationName: 'Stored Org', organizationalUnit: '', countryName: 'GB', stateOrProvinceName: '',
            localityName: '', streetAddress: '', postalCode: '',
        });
        assert.equal(certRequest({ ...certForm(false, 'ca'), name: 'web' }, subjects).subject, undefined, 'the default is the signer\'s');
    });

    await t.test('SAN entries are DNS names, wildcards or IP addresses', () => {
        for (const entry of ['web.example.test', '*.example.test', 'localhost', 'a-b.c1', '10.0.0.1', '::1', '2001:db8::1', '999.1.1.1']) {
            assert.ok(validSAN(entry), entry);
        }
        for (const entry of ['10.0.0.0/8', 'example.test.', '*.', '*', 'a.*.test', '-a.test', 'a-.test', 'a..test', 'under_score.test', 'x'.repeat(64) + '.test', ':::1']) {
            assert.ok(!validSAN(entry), entry);
        }
        const errors = certFormErrors({ ...certForm(false, 'ca'), name: 'web', san: 'ok.example.test, 10.0.0.0/8, bad_name' });
        assert.equal(errors.san, "10.0.0.0/8, bad_name aren't DNS names, wildcards or IP addresses");
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
    assert.equal(certValidity({ name: 'web', serial: '1', not_before: '2000-01-01T00:00:00Z', not_after: '2999-01-01T00:00:00Z' }), 'valid');
    assert.equal(certValidity({ name: 'web', serial: '1', not_after: '2000-01-01T00:00:00Z' }), 'expired');
    assert.equal(certValidity({ name: 'web', serial: '1', not_before: '2999-01-01T00:00:00Z', not_after: '2999-12-31T00:00:00Z' }), 'pending');
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

        await api.listCerts(client, { offset: 10, limit: 5, is_ca: true, tags: ['prod', 'web'] });
        await api.getCert(client, { name: 'web' }, true);
        await api.getPrivateKey(client, { name: 'web', serial: '1' });
        await api.createCA(client, { name: 'ca' });
        await api.renewCA(client, { name: 'ca', serial: '2' }, { expiry: Day });
        await api.createCert(client, { name: 'web', san: ['web.example.test'] }, { name: 'ca' });
        await api.renewCert(client, { name: 'web' });
        await api.updateCert(client, { name: 'web', serial: '1' }, { enabled: false });

        assert.deepEqual(requests.map((r) => `${r.method} ${r.url.pathname}${r.url.search}`), [
            'GET /api/cert?offset=10&limit=5&is_ca=true&tags=prod&tags=web',
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

test('subjects', async (t) => {
    await t.test('a new subject needs a field', () => {
        assert.equal(subjectCreateRequest({ organizationName: ' ', countryName: '' }), undefined);
        assert.deepEqual(subjectCreateRequest({ organizationName: ' Example ', countryName: '' }), { organizationName: 'Example' });
    });

    await t.test('an update has the fields which changed, and empty ones removed', () => {
        const original = { organizationName: 'Example', countryName: 'GB' };
        assert.equal(subjectUpdateRequest(original, { ...original }), undefined, 'nothing changed');
        assert.deepEqual(subjectUpdateRequest(original, { organizationName: 'Example', countryName: '', localityName: ' London ' }), { countryName: '', localityName: 'London' });
        assert.equal(subjectUpdateRequest(original, { organizationName: '', countryName: '' }), undefined, 'a field is kept');
    });

    await t.test('requests', async () => {
        const { client, requests } = fakeClient((method) => method === 'DELETE' ? json(204) : json(method === 'POST' ? 201 : 200, method === 'GET' ? { count: 0 } : { id: 7, certs: 0 }));
        await api.listSubjects(client, 100, 50);
        await api.getSubject(client, 7);
        await api.createSubject(client, { organizationName: 'Example' });
        await api.updateSubject(client, 7, { countryName: '' });
        await api.deleteSubject(client, 7);
        assert.deepEqual(requests.map((r) => `${r.method} ${r.url.pathname}${r.url.search}`), [
            'GET /api/subject?offset=100&limit=50',
            'GET /api/subject/7',
            'POST /api/subject',
            'PATCH /api/subject/7',
            'DELETE /api/subject/7',
        ]);
        assert.deepEqual(requests[3].body, { countryName: '' });
    });
});
