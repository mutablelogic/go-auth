import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { Client } from '@mutablelogic/go-server/api';
import type { Change, ChangeFilter, ChangesController } from '@mutablelogic/go-server/broadcaster';
import * as api from '../src/ldap/httpclient.ts';
import { addable, carryForm, classClosure, entryAttrs, entryForm, entryFormErrors, entrySchema, formFields, isPosix, namingAttr, namingChoices, newEntry, passwordForm, passwordFormErrors, passwordRequest } from '../src/ldap/form.ts';
import type { AttributeType, ObjectClass } from '../src/ldap/schema.ts';
import { listAll, schemaIs, schemaMatches } from '../src/ldap/controller.ts';
import { GroupController, LdapStatusController, ObjectController, UserController } from '../src/ldap/controller.ts';
import {
    binarySize, dnKey, entryKind, escapeDN, escapeFilter, syntaxName, first, hasChildren, hasClass, isBranch, isCounter, memberCount, isBinary, parentDN, rdn, rdnValue, sameDN, searchFilter, splitDN, valueText, values,
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
        onConnect() { return this; },
        onDisconnect() { return this; },
        onShutdown() { return this; },
        onError() { return this; },
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
        assert.equal(binarySize({ base64: 'AQI=' }), 2);
        assert.equal(binarySize({ base64: 'AQ==' }), 1);
        assert.equal(binarySize({ base64: '' }), 0);
    });

    await t.test('DNs', () => {
        assert.deepEqual(splitDN('cn=a\\,b, ou=x,dc=y'), ['cn=a\\,b', 'ou=x', 'dc=y'], 'escaped commas');
        assert.equal(rdn(object.dn), 'uid=alice');
        assert.equal(rdnValue('cn=Smith\\, J,ou=x'), 'Smith, J');
        assert.equal(rdnValue('cn=a\\2cb,ou=x'), 'a,b', 'hex escapes');
        assert.equal(rdnValue('uid=Jos\\c3\\a9,ou=users'), 'José', 'UTF-8 hex escapes');
        assert.equal(rdnValue('uid=Jos\u00e9 ,ou=users'), 'José', 'not escaped');
        assert.equal(parentDN('uid=x,ou=team\\ ,dc=test'), 'ou=team\\ ,dc=test', 'an escaped trailing space');
        assert.deepEqual(splitDN(' ou=a\\  , dc=test '), ['ou=a\\ ', 'dc=test']);
        assert.ok(!sameDN('ou=team\\ ,dc=test', 'ou=team,dc=test'));
        assert.equal(dnKey('UID=Alice, OU=Users ,dc=Test'), 'uid=alice,ou=users,dc=test', 'the same for the same DNs');
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

    await t.test('status is read again when changes may have been missed', async () => {
        const { changes } = fakeChanges();
        let listener: ((change?: Change) => void) | undefined;
        (changes as unknown as { on: (f: unknown, fn: (change?: Change) => void) => void }).on = (_, fn) => { listener = fn; };
        const status = new LdapStatusController({ host: 'ldap', port: 636, user: 'cn=admin', connected: true, base_dn: 'dc=test' }, changes,
            async () => ({ host: 'ldap', port: 636, user: 'cn=admin', connected: false, base_dn: 'dc=test' }));
        listener?.(undefined);
        await new Promise((resolve) => setTimeout(resolve, 0));
        assert.equal(status.current.connected, false);
    });

    await t.test("users follow groups' changes, and groups users'", async () => {
        const { client, requests } = fakeClient(() => json(200, { count: 0 }));
        const { changes, send } = fakeChanges();
        const users = new UserController(client, { changes });
        const groups = new GroupController(client, { changes });
        await users.list.refresh();
        await groups.list.refresh();
        const count = (path: string) => requests.filter((r) => r.url.pathname === path).length;
        const wait = () => new Promise((resolve) => setTimeout(resolve, 50));
        let before = count('/api/ldap/user');
        send({ schema: 'ldap', table: 'group', action: 'update', row: 'eng' });
        await wait();
        assert.ok(count('/api/ldap/user') > before, "a group's members changed");
        before = count('/api/ldap/group');
        send({ schema: 'ldap', table: 'user', action: 'update', row: 'alice' });
        await wait();
        assert.ok(count('/api/ldap/group') > before, "a user's groups changed");
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

        // Any change is of all the entries, as changes which arrive together
        // are only the last
        let changed = 0;
        objects.onChange(() => changed++);
        send({ schema: 'ldap', table: 'object', action: 'create', row: 'ou=x,ou=a,dc=test' });
        send({ schema: 'ldap', table: 'user', action: 'create', row: 'alice' });
        send({ schema: 'ldap', table: 'connection', action: 'delete' });
        assert.equal(changed, 2);
    });
});

// The users' classes, and the attribute types, of an OpenLDAP directory
const classes: ObjectClass[] = [
    { numericOid: '1', name: ['inetOrgPerson'], superClasses: ['organizationalPerson'], may: ['displayName', 'givenName', 'jpegPhoto', 'mail', 'uid'] },
    { numericOid: '2', name: ['organizationalPerson'], superClasses: ['person'], may: ['telephoneNumber'] },
    { numericOid: '3', name: ['person'], superClasses: ['top'], must: ['sn', 'cn'], may: ['description', 'userPassword'] },
    { numericOid: '4', name: ['posixAccount'], superClasses: ['top'], must: ['cn', 'uid', 'uidNumber', 'gidNumber', 'homeDirectory'], may: ['loginShell', 'userPassword'] },
    { numericOid: '5', name: ['top'], must: ['objectClass'] },
];
const types: AttributeType[] = [
    { numericOid: 'n', name: ['name'], syntax: '1.3.6.1.4.1.1466.115.121.1.15{32768}' },
    ...['cn', 'sn', 'givenName'].map((n) => ({ numericOid: n, name: [n], superType: 'name' })),
    ...['uidNumber', 'gidNumber'].map((n) => ({ numericOid: n, name: [n], syntax: '1.3.6.1.4.1.1466.115.121.1.27', singleValue: true })),
    ...['homeDirectory', 'loginShell', 'mail', 'displayName', 'uid', 'description', 'telephoneNumber', 'objectClass'].map((n) => ({ numericOid: n, name: [n], syntax: '1.3.6.1.4.1.1466.115.121.1.26' })),
    { numericOid: 'p', name: ['jpegPhoto'], syntax: '1.3.6.1.4.1.1466.115.121.1.28' },
    { numericOid: 'w', name: ['userPassword'], syntax: '1.3.6.1.4.1.1466.115.121.1.40' },
];

test('forms', async (t) => {
    const schema = entrySchema('user', classes, types);
    const alice: LdapObject = { dn: 'uid=alice,ou=users,dc=test', attrs: { uid: ['alice'], cn: ['Alice Smith'], sn: ['Smith'], mail: ['alice@example.com'], telephoneNumber: ['1', '2'], uidNumber: ['1001'], gidNumber: ['1001'] } };

    await t.test('the schema is what the classes must and may have', () => {
        assert.deepEqual(schema.must, ['sn', 'cn', 'uid', 'uidNumber', 'gidNumber', 'homeDirectory', 'objectClass']);
        assert.ok(schema.may.includes('mail'));
        assert.ok(!schema.may.includes('cn'), "what's required isn't optional");
        assert.ok(isPosix(schema));
        assert.equal(namingAttr(schema), 'uid');
        assert.equal(namingAttr(entrySchema('user', [{ numericOid: 'u', name: ['user'], must: ['cn'] }], types)), 'cn', 'Active Directory');
    });

    await t.test("a new user's fields are what it must have, which the server doesn't set, and those which are common", () => {
        const form = entryForm(schema);
        assert.ok(form.allocateGID, 'its group ID is its user ID');
        assert.deepEqual(formFields(form), ['cn', 'givenName', 'sn', 'displayName', 'mail', 'homeDirectory', 'loginShell', 'description']);
        form.allocateGID = false;
        assert.ok(formFields(form).includes('gidNumber'), 'its own group ID');
        assert.deepEqual(addable(form), ['telephoneNumber'], 'not binary, nor the name, nor the password');
        form.added.push('telephoneNumber');
        assert.equal(formFields(form).at(-1), 'telephoneNumber');
    });

    await t.test('a new user needs what it must have, and its defaults are filled', () => {
        const form = entryForm(schema);
        assert.deepEqual(Object.keys(entryFormErrors(form)).sort(), ['cn', 'homeDirectory', 'name', 'sn']);
        Object.assign(form, { name: ' bob ', password: 'a', confirm: 'b' });
        Object.assign(form.values, { cn: 'Bob Jones', sn: 'Jones', mail: 'bob' });
        assert.deepEqual(Object.keys(entryFormErrors(form)).sort(), ['confirm', 'mail'], 'the home directory has a default');
        form.confirm = 'a';
        form.values.mail = 'bob@example.com';
        form.allocateGID = false;
        form.values.gidNumber = 'x';
        assert.deepEqual(Object.keys(entryFormErrors(form)), ['gidNumber'], 'a number');
        form.values.gidNumber = '500';
        assert.deepEqual(entryFormErrors(form), {});
        assert.deepEqual(entryAttrs(form), { cn: ['Bob Jones'], sn: ['Jones'], mail: ['bob@example.com'], gidNumber: ['500'], homeDirectory: ['/home/bob'], userPassword: ['a'] });
    });

    await t.test('an edited user has what changed, emptied ones deleted, and its name, when renamed', () => {
        const form = entryForm(schema, alice);
        assert.equal(form.name, 'alice');
        assert.ok(!form.allocateGID);
        assert.equal(form.values.cn, 'Alice Smith');
        assert.ok(formFields(form).includes('gidNumber'), 'its group ID');
        assert.ok(!formFields(form).includes('telephoneNumber'), 'not more than one value');
        assert.ok(!formFields(form).includes('uidNumber'), 'allocated');
        assert.deepEqual(entryAttrs(form), {}, 'nothing changed');
        Object.assign(form.values, { mail: '', givenName: 'Alice', homeDirectory: '/home/alice' });
        assert.deepEqual(entryFormErrors(form), {});
        assert.deepEqual(entryAttrs(form), { givenName: ['Alice'], mail: null, homeDirectory: ['/home/alice'] });
        form.values.sn = '';
        assert.ok(entryFormErrors(form).sn, 'required');
        form.name = 'alicia';
        assert.deepEqual(entryAttrs(form).uid, ['alicia']);
    });

    await t.test("an existing user's schema is of its own classes, by name or OID, and their superiors", () => {
        assert.deepEqual(classClosure(classes, ['inetOrgPerson']).map((c) => c.name?.[0]), ['inetOrgPerson', 'organizationalPerson', 'person', 'top']);
        assert.deepEqual(classClosure(classes, ['4']).map((c) => c.name?.[0]), ['posixAccount', 'top'], 'by OID');
        const own = entrySchema('user', classClosure(classes, ['top', 'inetOrgPerson']), types);
        const form = entryForm(own, alice);
        assert.ok(!formFields(form).includes('homeDirectory'), 'not a posixAccount');
        assert.deepEqual(entryFormErrors(form), {});
    });

    await t.test("what wasn't changed isn't sent, even with spaces, and a rename keeps the name's other values", () => {
        const spaced: LdapObject = { ...alice, attrs: { ...alice.attrs, description: [' Spaced '], uid: ['alice', 'login-alias'] } };
        const form = entryForm(schema, spaced);
        assert.deepEqual(entryAttrs(form), {});
        form.values.description = 'Spaced';
        assert.deepEqual(entryAttrs(form), { description: ['Spaced'] });
        form.values.description = ' Spaced ';
        form.name = 'alicia';
        assert.deepEqual(entryAttrs(form), { uid: ['alicia', 'login-alias'] });
    });

    await t.test('a password is generated, or typed twice', () => {
        const form = passwordForm();
        assert.deepEqual(passwordFormErrors(form), {});
        assert.deepEqual(passwordRequest(form), {});
        form.generate = false;
        assert.ok(passwordFormErrors(form).password);
        Object.assign(form, { password: 'x', confirm: 'y' });
        assert.ok(passwordFormErrors(form).confirm);
        form.confirm = 'x';
        assert.deepEqual(passwordFormErrors(form), {});
        assert.deepEqual(passwordRequest(form), { new: 'x' });
    });
});

test('listAll', async () => {
    const pages: [number, number][] = [];
    const items = await listAll(async (offset, limit) => {
        pages.push([offset, limit]);
        return { count: 2500, body: Array.from({ length: Math.min(limit, 2500 - offset) }, (_, i) => offset + i) };
    });
    assert.equal(items.length, 2500);
    assert.deepEqual(pages, [[0, 1000], [1000, 1000], [2000, 1000]]);
    assert.deepEqual(await listAll(async () => ({ count: 5 })), [], 'an empty page');
});

test('groups', async (t) => {
    await t.test('members, by DN other than itself, or by name', () => {
        const dn = 'cn=eng,ou=groups,dc=test';
        assert.equal(memberCount({ dn, attrs: { member: [dn] } }), 0, 'itself');
        assert.equal(memberCount({ dn, attrs: { member: [dn, 'uid=a,ou=users,dc=test', 'UID=A,ou=users,dc=test'], uniqueMember: ['uid=b,ou=users,dc=test'] } }), 2);
        assert.equal(memberCount({ dn, attrs: { memberUid: ['a', 'b', 'c'], member: ['uid=a,ou=users,dc=test'] } }), 3);
    });

    await t.test("a group's form hides its members and ID, which the server sets", () => {
        const groupClasses: ObjectClass[] = [
            { numericOid: 'g', name: ['groupOfNames'], superClasses: ['top'], must: ['member', 'cn'], may: ['description', 'ou', 'owner'] },
            { numericOid: 'p', name: ['posixGroup'], superClasses: ['top'], must: ['gidNumber'], may: ['memberUid', 'userPassword'] },
            { numericOid: '5', name: ['top'], must: ['objectClass'] },
        ];
        const schema = entrySchema('group', groupClasses, [...types, ...['member', 'ou', 'owner', 'memberUid'].map((n) => ({ numericOid: n, name: [n], syntax: '1.3.6.1.4.1.1466.115.121.1.15' }))]);
        assert.equal(namingAttr(schema), 'cn');
        const form = entryForm(schema);
        assert.ok(!form.allocateGID);
        assert.deepEqual(formFields(form), ['description']);
        assert.deepEqual(addable(form), ['ou', 'owner'], 'not members, nor the password');
        form.name = 'eng';
        form.values.description = 'Engineers';
        assert.deepEqual(entryFormErrors(form), {});
        assert.deepEqual(entryAttrs(form), { description: ['Engineers'] });
    });
});

test('objects', async () => {
    assert.equal(hasChildren({ dn: 'ou=a', attrs: { hasSubordinates: ['TRUE'] } }), true);
    assert.equal(hasChildren({ dn: 'cn=a', attrs: { hasSubordinates: ['FALSE'] } }), false);
    assert.equal(hasChildren({ dn: 'cn=a', attrs: {} }), undefined, "when the directory doesn't say");
    assert.equal(entryKind({ dn: 'ou=a', attrs: { objectClass: ['top', 'organizationalUnit'] } }), 'container');
    assert.equal(entryKind({ dn: 'uid=a', attrs: { objectClass: ['inetOrgPerson', 'posixAccount'] } }), 'person');
    assert.equal(entryKind({ dn: 'cn=a', attrs: { objectClass: ['groupOfUniqueNames'] } }), 'group');
    assert.equal(entryKind({ dn: 'cn=a', attrs: { objectClass: ['device'] } }), 'entry');

    // Branches are in the tree, and leaves in the table
    assert.ok(isBranch({ dn: 'ou=a', attrs: { objectClass: ['organizationalUnit'], hasSubordinates: ['FALSE'] } }), 'an empty container');
    assert.ok(isBranch({ dn: 'cn=a', attrs: { objectClass: ['device'], hasSubordinates: ['TRUE'] } }), 'an entry with entries under it');
    assert.ok(!isBranch({ dn: 'uid=a', attrs: { objectClass: ['inetOrgPerson'], hasSubordinates: ['FALSE'] } }));
    assert.ok(!isBranch({ dn: 'uid=a', attrs: { objectClass: ['inetOrgPerson'] } }), "a person, when the directory doesn't say");

    // The entries with the next IDs, directly under the base DN
    assert.ok(isCounter('cn=lastuid,dc=example,dc=test', 'dc=example,dc=test'));
    assert.ok(isCounter('CN=LastGID, DC=Example,DC=Test', 'dc=example,dc=test'));
    assert.ok(!isCounter('cn=lastuid,ou=users,dc=example,dc=test', 'dc=example,dc=test'));
});

test('schema page', async () => {
    assert.equal(syntaxName('1.3.6.1.4.1.1466.115.121.1.15'), 'Directory String');
    assert.equal(syntaxName('1.3.6.1.4.1.1466.115.121.1.26{256}'), 'IA5 String {256}');
    assert.equal(syntaxName('1.2.3'), '1.2.3', 'not a known one');
    assert.equal(syntaxName(), '');

    const mail: AttributeType = { numericOid: '0.9.2342.19200300.100.1.3', name: ['mail', 'rfc822Mailbox'], description: 'RFC1274: RFC822 Mailbox' };
    assert.ok(schemaMatches(mail, ''));
    assert.ok(schemaMatches(mail, 'MAI'), 'a name, in any case');
    assert.ok(schemaMatches(mail, 'rfc822mail'), 'another name');
    assert.ok(schemaMatches(mail, '19200300'), 'its OID');
    assert.ok(schemaMatches(mail, 'mailbox'), 'its description');
    assert.ok(!schemaMatches(mail, 'phone'));

    // Identifiers in any case, as some OIDs are descriptors
    const config: ObjectClass = { numericOid: 'nsCertConfig-oid', name: ['nsCertConfig'] };
    assert.ok(schemaIs(config, 'NSCERTCONFIG-OID'));
    assert.ok(schemaIs(config, 'nscertconfig'));
    assert.ok(!schemaIs(config, 'nsCert'));
    assert.ok(schemaMatches(config, 'CONFIG-OID'));
});

test('entries', async (t) => {
    const all: ObjectClass[] = [
        ...classes,
        { numericOid: 'ou', name: ['organizationalUnit'], superClasses: ['top'], classKind: 'STRUCTURAL', must: ['ou'], may: ['description', 'l'] },
    ];
    const types2 = [...types, ...['ou', 'l'].map((n) => ({ numericOid: n, name: [n], syntax: '1.3.6.1.4.1.1466.115.121.1.15' }))];

    await t.test('a DN value is escaped', () => {
        assert.equal(escapeDN('Smith, Alice'), 'Smith\\, Alice');
        assert.equal(escapeDN(' #a+b=c '), '\\ #a\\+b\\=c\\ ');
        assert.equal(escapeDN('#x'), '\\#x');
        assert.equal(escapeDN('a\\ '), 'a\\\\\\ ', 'a backslash, then a space last');
    });

    await t.test("an entry is named by what its class must have, best first", () => {
        assert.deepEqual(namingChoices(entrySchema('entry', classClosure(all, ['organizationalUnit']), types2)), ['ou', 'description', 'l']);
        assert.equal(namingChoices(entrySchema('entry', classClosure(all, ['inetOrgPerson']), types2))[0], 'cn');
    });

    await t.test('a new entry has its classes, and its name, in its DN', () => {
        const form = entryForm(entrySchema('entry', classClosure(all, ['organizationalUnit']), types2, 'ou'));
        assert.equal(namingAttr(form.schema), 'ou');
        assert.deepEqual(formFields(form), ['description'], 'not its name');
        form.name = 'Sales, EMEA';
        form.values.description = 'Sellers';
        assert.deepEqual(entryFormErrors(form), {});
        assert.deepEqual(newEntry(form, 'dc=test'), {
            dn: 'ou=Sales\\, EMEA,dc=test',
            attrs: { description: ['Sellers'], objectClass: ['top', 'organizationalUnit'], ou: ['Sales, EMEA'] },
        });
    });

    await t.test("what's typed is kept by attribute, when the class, or the attribute which names it, changes", () => {
        const typed: Record<string, string> = {};
        const added: string[] = [];
        const person = (naming: string) => entrySchema('entry', classClosure(all, ['inetOrgPerson']), types2, naming);
        let form = carryForm(person('cn'), undefined, typed, added);
        form.name = 'Alice Smith';
        form.values.uid = 'alice';
        form.values.sn = 'Smith';
        form.added.push('mail');
        form.values.mail = 'alice@example.com';

        // Named by uid: the name is alice, and Alice Smith is the cn, which
        // it must have
        form = carryForm(person('uid'), form, typed, added);
        assert.equal(form.name, 'alice');
        assert.equal(form.values.cn, 'Alice Smith');
        assert.deepEqual(entryFormErrors(form), {});
        assert.deepEqual(newEntry(form, 'dc=test').attrs.cn, ['Alice Smith']);

        // An organizational unit can't have a mail address, which isn't
        // added, or sent, but is kept, for a change back
        form = carryForm(entrySchema('entry', classClosure(all, ['organizationalUnit']), types2, 'ou'), form, typed, added);
        assert.equal(form.name, '', 'no ou was typed');
        assert.deepEqual(form.added, []);
        form.name = 'sales';
        assert.equal(newEntry(form, 'dc=test').attrs.mail, undefined);
        form = carryForm(person('uid'), form, typed, added);
        assert.equal(form.name, 'alice');
        assert.equal(form.values.mail, 'alice@example.com');
        assert.deepEqual(form.added, ['mail'], 'shown again');
        assert.deepEqual(newEntry(form, 'dc=test').attrs.mail, ['alice@example.com']);
    });

    await t.test("an existing entry is named by its RDN's attribute", () => {
        const person: LdapObject = { dn: 'cn=Bob Jones,ou=x,dc=test', attrs: { objectClass: ['inetOrgPerson'], cn: ['Bob Jones'], sn: ['Jones'], uid: ['bob'] } };
        const form = entryForm(entrySchema('entry', classClosure(all, ['inetOrgPerson']), types2, 'cn'), person);
        assert.equal(form.name, 'Bob Jones');
        assert.ok(formFields(form).includes('uid'), 'its uid, which is not its name');
        assert.ok(!formFields(form).includes('cn'));
        form.name = 'Robert Jones';
        assert.deepEqual(entryAttrs(form), { cn: ['Robert Jones'] });
    });
});
