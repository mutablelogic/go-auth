// The LDAP API's types, which go-auth's ldap/httphandler serves, and
// helpers for entries: their attributes, in any case, and their DNs

// A value is a string, or, when it isn't UTF-8, such as a certificate, its
// bytes in base64
export type AttrValue = string | { base64: string };

// Attrs are an entry's attributes, by name, with a list of values each
export type Attrs = Record<string, AttrValue[] | null>;

// LdapObject is an entry, by its DN
export interface LdapObject {
    dn: string;
    attrs?: Attrs;
}

// ObjectList is a page of entries, and how many match
export interface ObjectList {
    count: number;
    body?: LdapObject[];
}

// ListRequest is the paging, filter and attributes of a list
export interface ListRequest {
    offset?: number;
    limit?: number;
    // filter is an LDAP filter, such as (cn=a*)
    filter?: string;
    attr?: string[];
}

// ObjectListRequest lists the entries under the base DN, or the prefix, or
// only those directly under it, with children
export interface ObjectListRequest extends ListRequest {
    prefix?: string;
    children?: boolean;
}

// UserListRequest lists the users, or a group's members
export interface UserListRequest extends ListRequest {
    group?: string;
}

// GroupListRequest lists the groups, or a user's
export interface GroupListRequest extends ListRequest {
    user?: string;
}

// ObjectClassKind and AttributeUsage are a class's kind, and an attribute
// type's usage
export type ObjectClassKind = 'ABSTRACT' | 'STRUCTURAL' | 'AUXILIARY';
export type AttributeUsage = 'userApplications' | 'directoryOperation' | 'distributedOperation' | 'dSAOperation';

// ObjectClass is one of the directory's object classes
export interface ObjectClass {
    numericOid: string;
    name?: string[];
    description?: string;
    superClasses?: string[];
    classKind?: ObjectClassKind;
    must?: string[];
    may?: string[];
    obsolete?: boolean;
    extensions?: Record<string, string[]>;
}

// AttributeType is one of the directory's attribute types
export interface AttributeType {
    numericOid: string;
    name?: string[];
    description?: string;
    superType?: string;
    usage?: AttributeUsage;
    syntax?: string;
    obsolete?: boolean;
    singleValue?: boolean;
    collective?: boolean;
    noUserModification?: boolean;
    extensions?: Record<string, string[]>;
}

// ObjectClassList and AttributeTypeList are pages of the schema
export interface ObjectClassList {
    count: number;
    body?: ObjectClass[];
}

export interface AttributeTypeList {
    count: number;
    body?: AttributeType[];
}

// ObjectClassListRequest and AttributeTypeListRequest filter the schema
export interface ObjectClassListRequest {
    offset?: number;
    limit?: number;
    filter?: string;
    kind?: ObjectClassKind;
    superior?: string[];
    must?: string[];
    may?: string[];
    obsolete?: boolean;
    // for is user or group, for only the classes users, or groups, are
    // created with, and those they inherit from
    for?: 'user' | 'group';
}

export interface AttributeTypeListRequest {
    offset?: number;
    limit?: number;
    filter?: string;
    usage?: AttributeUsage;
    superior?: string;
    obsolete?: boolean;
    singleValue?: boolean;
    collective?: boolean;
    noUserModification?: boolean;
}

// PasswordRequest changes a password, with the old one, which is checked,
// or resets it, without, to the new one, or one which is generated
export interface PasswordRequest {
    old?: string;
    new?: string;
}

// PasswordResponse is the entry, with the password, when it's generated
export interface PasswordResponse extends LdapObject {
    'generated-password'?: string;
}

// LdapStatus is the directory, and whether the manager is connected to it,
// which the configuration's ldap section has
export interface LdapStatus {
    host: string;
    port: number;
    user: string;
    connected: boolean;
    base_dn: string;
    // user_dn and group_dn are the users' and groups' DNs, when there are
    // users and groups
    user_dn?: string;
    group_dn?: string;
}

// The changes' schema, and their tables
export const ChangeSchema = 'ldap';
export const TableObject = 'object';
export const TableUser = 'user';
export const TableGroup = 'group';
export const TableConnection = 'connection';

///////////////////////////////////////////////////////////////////////////////
// ATTRIBUTES

// values returns the entry's values of the attribute, whose name is in any
// case
export function values(object: LdapObject, name: string): AttrValue[] {
    for (const [key, list] of Object.entries(object.attrs ?? {})) {
        if (key.toLowerCase() === name.toLowerCase()) {
            return list ?? [];
        }
    }
    return [];
}

// first returns the entry's first value of the attribute, as text, or
// undefined
export function first(object: LdapObject, name: string): string | undefined {
    const value = values(object, name)[0];
    return value === undefined ? undefined : valueText(value);
}

// isBinary returns whether the value isn't UTF-8, so it's in base64
export function isBinary(value: AttrValue): value is { base64: string } {
    return typeof value === 'object' && value !== null && 'base64' in value;
}

// valueText returns the value, or, for one which isn't UTF-8, its size
export function valueText(value: AttrValue): string {
    if (!isBinary(value)) {
        return value;
    }
    return `${binarySize(value)} bytes`;
}

// binarySize returns how many bytes a value in base64 has
export function binarySize(value: { base64: string }): number {
    // The padding is counted from the end, rather than with a regular
    // expression, which would be slow on many '='
    let length = value.base64.length;
    while (length > 0 && value.base64[length - 1] === '=') {
        length--;
    }
    return Math.floor((length * 3) / 4);
}

// hasClass returns whether the entry has the object class, in any case
export function hasClass(object: LdapObject, name: string): boolean {
    return values(object, 'objectClass').some((value) => !isBinary(value) && value.toLowerCase() === name.toLowerCase());
}

// memberCount returns how many members a group has: those by DN, other
// than itself, which a group that needs a member has, or by name, in
// memberUid, which can be the same users, whichever is more
export function memberCount(group: LdapObject): number {
    const dns = new Set<string>();
    for (const attr of ['member', 'uniqueMember']) {
        for (const value of values(group, attr)) {
            if (typeof value === 'string' && !sameDN(value, group.dn)) {
                dns.add(value.toLowerCase());
            }
        }
    }
    return Math.max(dns.size, values(group, 'memberUid').length);
}

// hasChildren returns whether the entry has entries under it, as its
// hasSubordinates says, or undefined, when the directory doesn't say
export function hasChildren(object: LdapObject): boolean | undefined {
    const value = first(object, 'hasSubordinates');
    return value === undefined ? undefined : value.toUpperCase() === 'TRUE';
}

// entryKind returns what an entry is, from its object classes, for its
// icon: a container, such as an organizational unit, a person, a group, or
// another entry
export function entryKind(object: LdapObject): 'container' | 'person' | 'group' | 'entry' {
    const has = (...names: string[]) => names.some((name) => hasClass(object, name));
    if (has('person', 'user', 'account', 'inetOrgPerson', 'posixAccount')) {
        return 'person';
    } else if (has('group', 'groupOfNames', 'groupOfUniqueNames', 'groupOfMembers', 'posixGroup')) {
        return 'group';
    } else if (has('organizationalUnit', 'organization', 'domain', 'dcObject', 'container', 'builtinDomain')) {
        return 'container';
    }
    return 'entry';
}

// isBranch returns whether an entry is a branch, shown in a tree: one which
// has entries under it, or is a container, such as an organizational unit,
// which can have them, rather than a leaf, such as a person
export function isBranch(object: LdapObject): boolean {
    return hasChildren(object) === true || entryKind(object) === 'container';
}

// isCounter returns whether the DN is one of the entries which have the
// next user or group ID, cn=lastuid and cn=lastgid under the base DN, which
// the server doesn't delete
export function isCounter(dn: string, base: string): boolean {
    return ['lastuid', 'lastgid'].some((name) => sameDN(dn, `cn=${name},${base}`));
}

// Syntaxes are the names of the well-known attribute syntaxes (RFC 4517),
// by the last part of their OIDs, under 1.3.6.1.4.1.1466.115.121.1
const Syntaxes: Record<string, string> = {
    '3': 'Attribute Type Description', '4': 'Audio', '16': 'DIT Content Rule Description',
    '17': 'DIT Structure Rule Description', '30': 'Matching Rule Description', '31': 'Matching Rule Use Description',
    '35': 'Name Form Description', '37': 'Object Class Description',
    '5': 'Binary', '6': 'Bit String', '7': 'Boolean', '8': 'Certificate', '9': 'Certificate List',
    '10': 'Certificate Pair', '11': 'Country String', '12': 'DN', '14': 'Delivery Method',
    '15': 'Directory String', '22': 'Facsimile Telephone Number', '24': 'Generalized Time',
    '26': 'IA5 String', '27': 'Integer', '28': 'JPEG', '34': 'Name and Optional UID', '36': 'Numeric String',
    '38': 'OID', '39': 'Other Mailbox', '40': 'Octet String', '41': 'Postal Address', '44': 'Printable String',
    '49': 'Supported Algorithm', '50': 'Telephone Number', '52': 'Telex Number', '53': 'UTC Time',
    '54': 'LDAP Syntax Description', '58': 'Substring Assertion',
};

// syntaxName returns a syntax's name, with its length, such as IA5 String
// {256}, or else its OID
export function syntaxName(oid?: string): string {
    if (!oid) {
        return '';
    }
    const match = /^1\.3\.6\.1\.4\.1\.1466\.115\.121\.1\.(\d+)(\{\d+\})?$/.exec(oid);
    const name = match ? Syntaxes[match[1]] : undefined;
    return name ? (match![2] ? `${name} ${match![2]}` : name) : oid;
}

///////////////////////////////////////////////////////////////////////////////
// DNS

// rdn returns the first RDN of the DN, such as uid=alice, as it is
export function rdn(dn: string): string {
    return splitDN(dn)[0] ?? '';
}

// rdnLabel returns the DN's first RDN, with its value unescaped, such as
// ou=Sales, EMEA, to show it, rather than ou=Sales\2C EMEA
export function rdnLabel(dn: string): string {
    const first = rdn(dn);
    const equals = first.indexOf('=');
    return equals < 0 ? first : `${first.slice(0, equals)}=${rdnValue(dn)}`;
}

// rdnValue returns the value of the DN's first RDN, unescaped, such as alice
export function rdnValue(dn: string): string {
    const first = rdn(dn);
    const equals = first.indexOf('=');
    return unescapeDN(equals < 0 ? first : first.slice(equals + 1));
}

// parentDN returns the DN of the entry's parent, or empty, for one without
// one
export function parentDN(dn: string): string {
    return splitDN(dn).slice(1).join(',');
}

// sameDN returns whether two DNs are the same, in any case, and spacing
// around their RDNs
export function sameDN(a: string, b: string): boolean {
    return dnKey(a) === dnKey(b);
}

// dnKey returns a DN in lower case, without spacing around its RDNs, which
// is the same for DNs which are the same, such as for a set of them
export function dnKey(dn: string): string {
    return splitDN(dn).map((part) => part.toLowerCase()).join(',');
}

// escapeDN escapes a value for an RDN (RFC 4514): a comma, plus, quote,
// backslash, angle brackets, semicolon and equals, a space or # first, and
// a space last, so it's one value
export function escapeDN(value: string): string {
    let escaped = '';
    for (let i = 0; i < value.length; i++) {
        const c = value[i];
        const first = i === 0 && (c === ' ' || c === '#');
        const last = i === value.length - 1 && c === ' ';
        escaped += ',+"\\<>;='.includes(c) || first || last ? `\\${c}` : c;
    }
    return escaped;
}

// splitDN returns the RDNs of the DN, at commas which aren't escaped,
// without the spaces around them, but with escaped ones, such as a
// trailing space which is part of a value
export function splitDN(dn: string): string[] {
    const parts: string[] = [];
    let part = '';
    // kept is how much of the part is escaped, which isn't trimmed
    let kept = 0;
    const push = () => {
        const trimmed = part.slice(0, kept) + part.slice(kept).trimEnd();
        parts.push(trimmed.trimStart());
        part = '';
        kept = 0;
    };
    for (let i = 0; i < dn.length; i++) {
        const c = dn[i];
        if (c === '\\' && i + 1 < dn.length) {
            part += c + dn[++i];
            kept = part.length;
        } else if (c === ',') {
            push();
        } else {
            part += c;
        }
    }
    if (part.trim() !== '' || parts.length > 0) {
        push();
    }
    return parts.filter((p) => p !== '');
}

// unescapeDN unescapes a value of an RDN, such as a\,b or a\2cb, whose hex
// escapes are the bytes of UTF-8, such as Jos\c3\a9
function unescapeDN(value: string): string {
    const bytes: number[] = [];
    const encoder = new TextEncoder();
    for (let i = 0; i < value.length; i++) {
        const c = value[i];
        const hex = value.slice(i + 1, i + 3);
        if (c === '\\' && /^[0-9a-fA-F]{2}$/.test(hex)) {
            bytes.push(parseInt(hex, 16));
            i += 2;
        } else if (c === '\\' && i + 1 < value.length) {
            bytes.push(...encoder.encode(value[++i]));
        } else {
            // A character, which can be two UTF-16 code units
            const point = value.codePointAt(i)!;
            const char = String.fromCodePoint(point);
            bytes.push(...encoder.encode(char));
            i += char.length - 1;
        }
    }
    return new TextDecoder().decode(new Uint8Array(bytes));
}

///////////////////////////////////////////////////////////////////////////////
// FILTERS

// escapeFilter escapes a value for an LDAP filter (RFC 4515), so it's
// matched as it is
export function escapeFilter(value: string): string {
    return value.replace(/[\\*()\0]/g, (c) => `\\${c.charCodeAt(0).toString(16).padStart(2, '0')}`);
}

// searchFilter returns a filter of the entries with the text in any of the
// attributes, such as (|(uid=*al*)(cn=*al*)), or undefined, without text
export function searchFilter(text: string, attrs: readonly string[]): string | undefined {
    text = text.trim();
    if (!text || attrs.length === 0) {
        return undefined;
    }
    const value = escapeFilter(text);
    const parts = attrs.map((attr) => `(${attr}=*${value}*)`);
    return parts.length === 1 ? parts[0] : `(|${parts.join('')})`;
}
