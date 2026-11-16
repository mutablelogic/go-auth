import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { Client } from '@mutablelogic/go-server/api';
import type { Change, ChangeFilter, ChangesController } from '@mutablelogic/go-server/broadcaster';
import * as api from '../src/ldap/httpclient.ts';
import { GroupController, LdapStatusController, ObjectController, UserController } from '../src/ldap/controller.ts';
import {
    binarySize, escapeFilter, first, hasClass, isBinary, parentDN, rdn, rdnValue, sameDN, searchFilter, splitDN, valueText, values,
    type LdapObject,
} from '../src/ldap/schema.ts';

// fakeClient returns a client whose fetch records each request, and
// returns the response of the function
function fakeClient(respond: (method: string, url: URL, body?: unknown) => Response) {
    const requests: { method: string; url: URL; body?: unknown; type?: string }[] = [];
    const client: Client = {
        base: 'http://localhost/api',
        fetch: (async (input: RequestInfo | URL, init: RequestInit = {}) => {
            const url = new URL(String(input));
            const method = init.method ?? 'GET';
            const type = (init.headers as Record<string, string> | undefined)?.['Content-Type'];
            const body = init.body === undefined ? undefined : type === 'text/plain' ? init.body : JSON.parse(String(init.body));
            requests.push({ method, url, body, type });
            return respond(method, url, body);
        }) as typeof fetch,
    };
    return { client, requests };
}

// fakeChanges returns changes which call the listeners whose filters match
function fakeChanges() {
    const listeners: { filters: ChangeFilter[]; fn: (change?: Change) => void }[] = [];
    const changes = {
        on(filter: ChangeFilter | ChangeFilter[], fn: (change?: Change) => void) {
            listeners.push({ filters: Array.isArray(filter) ? filter : [filter], fn });
            return this;
        },
        subscribe(filter: ChangeFilter | ChangeFilter[], fn: (change?: Change) => void) {
            this.on(filter, fn);
            return () => {};
        },
    };
    const send = (change: Change) => {
        for (const { filters, fn } of listeners) {
            if (filters.some((f) => (!f.schema || f.schema === change.schema) && (!f.table || f.table === change.table) && (!f.action || f.action === change.action))) {
                fn(change);
            }
        }
    };
    return { changes: changes as unknown as ChangesController, send };
}

const json = (status: number, body?: unknown) => new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
});

test('schema', async (t) => {
    const object: LdapObject = { dn: 'uid=alice,ou=users,dc=example,dc=test', attrs: { ObjectClass: ['top', 'inetOrgPerson'], CN: ['Alice'], jpegPhoto: [{ base64: 'AQIDBA==' }] } };

    await t.test('attributes, in any case', () => {
        assert.deepEqual(values(object, 'objectclass'), ['top', 'inetOrgPerson']);
        assert.equal(first(object, 'cn'), 'Alice');
        assert.equal(first(object, 'mail'), undefined);
        assert.ok(hasClass(object, 'INETORGPERSON'));
        assert.ok(!hasClass(object, 'posixAccount'));
    });

    await t.test('binary values', () => {
        const photo = values(object, 'jpegPhoto')[0];
        assert.ok(isBinary(photo));
        assert.equal(binarySize(photo as { base64: string }), 4);
        assert.equal(valueText(photo), '4 bytes');
        assert.equal(valueText('text'), 'text');
    });

    await t.test('DNs', () => {
        assert.deepEqual(splitDN('cn=a\\,b, ou=x,dc=y'), ['cn=a\\,b', 'ou=x', 'dc=y'], 'escaped commas');
        assert.equal(rdn(object.dn), 'uid=alice');
        assert.equal(rdnValue('cn=Smith\\, J,ou=x'), 'Smith, J');
        assert.equal(rdnValue('cn=a\\2cb,ou=x'), 'a,b', 'hex escapes');
        assert.equal(parentDN(object.dn), 'ou=users,dc=example,dc=test');
        assert.equal(parentDN('dc=test'), '');
        assert.ok(sameDN('UID=Alice, OU=Users,DC=Example,DC=Test', 'uid=alice,ou=users,dc=example,dc=test'));
        assert.ok(!sameDN('uid=bob,ou=users', 'uid=alice,ou=users'));
    });

    await t.test('filters', () => {
        assert.equal(escapeFilter('a*(b)\\'), 'a\\2a\\28b\\29\\5c');
        assert.equal(searchFilter('al', ['uid']), '(uid=*al*)');
        assert.equal(searchFilter(' al* ', ['uid', 'cn']), '(|(uid=*al\\2a*)(cn=*al\\2a*))');
        assert.equal(searchFilter('  ', ['uid']), undefined);
    });
});

test('httpclient', async () => {
    const { client, requests } = fakeClient((method, url) => method === 'GET' && !url.pathname.match(/ldap\/(user|group|object)\//)
        ? json(200, { count: 0 })
        : json(method === 'PUT' ? 201 : 200, { dn: 'cn=x' }));

    await api.listObjectClasses(client, { filter: 'person', kind: 'STRUCTURAL', must: ['cn', 'sn'], obsolete: false });
    await api.listAttributeTypes(client, { usage: 'userApplications', limit: 5 });
    await api.listUsers(client, { group: 'eng', attr: ['uid', 'cn'], offset: 0 });
    await api.getUser(client, 'alice');
    await api.createUser(client, 'alice', { cn: ['Alice'] }, true);
    await api.updateUser(client, 'alice', { description: null });
    await api.deleteUser(client, 'alice');
    await api.listGroups(client, { user: 'alice' });
    await api.addGroupUsers(client, 'eng', ['alice', 'bob']);
    await api.removeGroupUsers(client, 'eng', ['bob']);
    await api.listObjects(client, { prefix: 'ou=users', children: true });
    await api.getObject(client, 'ou=a/b,dc=test');
    await api.createObject(client, 'ou=a,dc=test', { objectClass: ['organizationalUnit'] });
    await api.bindObject(client, 'uid=alice,ou=users', 'secret Passw0rd!');
    await api.changePassword(client, 'uid=alice,ou=users', { old: 'a' });

    assert.deepEqual(requests.map((r) => `${r.method} ${r.url.pathname}${r.url.search}`), [
        'GET /api/ldap/class?filter=person&kind=STRUCTURAL&must=cn&must=sn&obsolete=false',
        'GET /api/ldap/attr?usage=userApplications&limit=5',
        'GET /api/ldap/user?group=eng&attr=uid&attr=cn&offset=0',
        'GET /api/ldap/user/alice',
        'PUT /api/ldap/user/alice?allocate_gid=true',
        'PATCH /api/ldap/user/alice',
        'DELETE /api/ldap/user/alice',
        'GET /api/ldap/group?user=alice',
        'POST /api/ldap/group/eng/user',
        'DELETE /api/ldap/group/eng/user',
        'GET /api/ldap/object?prefix=ou%3Dusers&children=true',
        'GET /api/ldap/object/ou%3Da%2Fb%2Cdc%3Dtest',
        'PUT /api/ldap/object/ou%3Da%2Cdc%3Dtest',
        'POST /api/ldap/object/uid%3Dalice%2Cou%3Dusers/bind',
        'POST /api/ldap/object/uid%3Dalice%2Cou%3Dusers/password',
    ]);
    assert.deepEqual(requests[4].body, { attrs: { cn: ['Alice'] } });
    assert.deepEqual(requests[5].body, { attrs: { description: null } }, 'null deletes');
    assert.deepEqual(requests[8].body, ['alice', 'bob']);
    assert.equal(requests[13].type, 'text/plain');
    assert.equal(requests[13].body, 'secret Passw0rd!', 'the password, as it is');

    // A wrong password is an error
    const wrong = fakeClient(() => json(401, { code: 401, reason: 'Invalid credentials' }));
    await assert.rejects(api.bindObject(wrong.client, 'uid=alice', 'wrong'));
});

test('controllers', async (t) => {
    await t.test('status follows the connection', () => {
        const { changes, send } = fakeChanges();
        const status = new LdapStatusController({ host: 'ldap', port: 636, user: 'cn=admin', connected: true, base_dn: 'dc=test' }, changes);
        const seen: boolean[] = [];
        status.subscribe((s) => seen.push(s.connected));
        send({ schema: 'ldap', table: 'connection', action: 'delete', row: 'ldap:636' });
        send({ schema: 'ldap', table: 'object', action: 'delete', row: 'cn=x' });
        send({ schema: 'other', table: 'connection', action: 'create' });
        send({ schema: 'ldap', table: 'connection', action: 'create', row: 'ldap:636' });
        assert.deepEqual(seen, [true, false, true]);
    });

    await t.test('users and groups are searched', async () => {
        const { client, requests } = fakeClient(() => json(200, { count: 1, body: [{ dn: 'uid=alice,ou=users' }] }));
        const users = new UserController(client);
        await users.setSearch('al');
        await users.setGroup('eng');
        assert.equal(users.list.current.items?.length, 1);
        const groups = new GroupController(client);
        await groups.setUser('alice');
        const queries = requests.map((r) => r.url.searchParams);
        assert.equal(queries[0].get('filter'), '(|(uid=*al*)(cn=*al*)(mail=*al*)(sn=*al*)(givenName=*al*))');
        assert.equal(queries[1].get('group'), 'eng');
        assert.equal(queries[2].get('user'), 'alice');
    });

    await t.test('objects load children, and say which parent changed', async () => {
        let call = 0;
        const { client, requests } = fakeClient(() => json(200, call++ === 0
            ? { count: 3, body: [{ dn: 'ou=a,dc=test' }, { dn: 'ou=b,dc=test' }] }
            : { count: 3, body: [{ dn: 'ou=c,dc=test' }] }));
        const { changes, send } = fakeChanges();
        const objects = new ObjectController(client, { changes });
        const children = await objects.children();
        assert.deepEqual(children.map((c) => c.dn), ['ou=a,dc=test', 'ou=b,dc=test', 'ou=c,dc=test'], 'every page');
        assert.equal(requests[0].url.searchParams.get('children'), 'true');
        assert.equal(requests[0].url.searchParams.get('prefix'), null, 'the base DN');
        assert.equal(requests[1].url.searchParams.get('offset'), '2');

        const parents: string[] = [];
        objects.onChange((parent) => parents.push(parent));
        send({ schema: 'ldap', table: 'object', action: 'create', row: 'ou=x,ou=a,dc=test' });
        send({ schema: 'ldap', table: 'object', action: 'update', row: 'ou=y,ou=b,dc=test', data: { previous: 'ou=y,ou=a,dc=test' } });
        send({ schema: 'ldap', table: 'user', action: 'create', row: 'alice' });
        assert.deepEqual(parents, ['ou=a,dc=test', 'ou=b,dc=test', 'ou=a,dc=test', '']);
    });
});
