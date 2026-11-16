// The LDAP module's forms: an entry's, such as a user's, which creates one,
// or edits one, and a password's, which sets one, or generates it. They're
// what their inputs set, what's wrong with them, and the request they send.
//
// An entry's form is made from its object classes, as the directory has
// them: the attributes they must have are required, and those they may have
// are offered, except those the server sets itself, such as the name, and
// IDs it allocates.

import { first, rdn, rdnValue, values, type Attrs, type AttributeType, type LdapObject, type ObjectClass, type PasswordRequest } from './schema.ts';

///////////////////////////////////////////////////////////////////////////////
// SCHEMA

// EntryKind is what an entry's form creates or edits
export type EntryKind = 'user' | 'group';

// EntrySchema is what entries of a kind are: their object classes, the
// attributes they must, and may, have, by the names the directory uses, in
// the classes' order, and the attributes' types, by any of their names, in
// lower case
export interface EntrySchema {
    kind: EntryKind;
    classes: string[];
    must: string[];
    may: string[];
    types: Map<string, AttributeType>;
}

// entrySchema returns the schema of entries of the kind, from their object
// classes, with those they inherit from, and the directory's attribute types
export function entrySchema(kind: EntryKind, classes: readonly ObjectClass[], types: readonly AttributeType[]): EntrySchema {
    const byName = new Map<string, AttributeType>();
    for (const type of types) {
        for (const name of type.name ?? []) {
            byName.set(name.toLowerCase(), type);
        }
    }
    const canonical = (name: string) => byName.get(name.toLowerCase())?.name?.[0] ?? name;
    const must: string[] = [];
    const may: string[] = [];
    const seen = new Set<string>();
    const add = (list: string[], names: readonly string[] = []) => {
        for (const name of names.map(canonical)) {
            if (!seen.has(name.toLowerCase())) {
                seen.add(name.toLowerCase());
                list.push(name);
            }
        }
    };
    // What one class must have is required, even when another may have it
    for (const c of classes) {
        add(must, c.must);
    }
    for (const c of classes) {
        add(may, c.may);
    }
    return { kind, classes: classes.flatMap((c) => c.name?.slice(0, 1) ?? []), must, may, types: byName };
}

// classClosure returns the classes, by any of their names, or OIDs, and
// those they inherit from, in the directory's order
export function classClosure(all: readonly ObjectClass[], names: readonly string[]): ObjectClass[] {
    const found = new Set<ObjectClass>();
    const matches = (c: ObjectClass, name: string) =>
        c.numericOid.toLowerCase() === name.toLowerCase() || (c.name ?? []).some((n) => n.toLowerCase() === name.toLowerCase());
    const walk = (name: string) => {
        for (const c of all) {
            if (!found.has(c) && matches(c, name)) {
                found.add(c);
                (c.superClasses ?? []).forEach(walk);
            }
        }
    };
    names.forEach(walk);
    return all.filter((c) => found.has(c));
}

// hasClass returns whether the schema's entries have the object class
export function schemaHasClass(schema: EntrySchema, name: string): boolean {
    return schema.classes.some((c) => c.toLowerCase() === name.toLowerCase());
}

// attrSyntax returns the attribute's syntax's OID, which it can inherit from
// its super type, without its length
export function attrSyntax(schema: EntrySchema, name: string): string | undefined {
    const seen = new Set<string>();
    for (let type = schema.types.get(name.toLowerCase()); type; type = type.superType ? schema.types.get(type.superType.toLowerCase()) : undefined) {
        if (type.syntax) {
            return type.syntax.replace(/\{\d+\}$/, '');
        } else if (seen.has(type.numericOid)) {
            return undefined;
        }
        seen.add(type.numericOid);
    }
    return undefined;
}

// Syntaxes, by OID, whose values are numbers, or aren't text
const IntegerSyntax = '1.3.6.1.4.1.1466.115.121.1.27';
const BinarySyntaxes = new Set(['4', '5', '8', '9', '10', '28', '40', '49'].map((n) => `1.3.6.1.4.1.1466.115.121.1.${n}`));

// isInteger and isBinaryAttr return whether the attribute's values are
// integers, or aren't text, such as a photo
export function isInteger(schema: EntrySchema, name: string): boolean {
    return attrSyntax(schema, name) === IntegerSyntax;
}

export function isBinaryAttr(schema: EntrySchema, name: string): boolean {
    const syntax = attrSyntax(schema, name);
    return !!syntax && BinarySyntaxes.has(syntax);
}

// namingAttr returns the attribute which names an entry of the schema: cn
// for groups, and for Active Directory's users, and else uid, as the server
// names them
export function namingAttr(schema: EntrySchema): string {
    if (schema.kind === 'group' || schemaHasClass(schema, 'user')) {
        return 'cn';
    }
    return ['posixAccount', 'account', 'inetOrgPerson'].some((c) => schemaHasClass(schema, c)) ? 'uid' : 'cn';
}

// Attributes the server sets, or which are changed elsewhere, such as
// passwords and members, which the form doesn't show
const Managed: Record<EntryKind, string[]> = {
    user: ['objectClass', 'uidNumber', 'userPassword', 'unicodePwd', 'sAMAccountName', 'userAccountControl'],
    group: ['objectClass', 'gidNumber', 'member', 'uniqueMember', 'memberUid', 'sAMAccountName', 'groupType'],
};

// Attributes which are offered, when the entries may have them, before
// those which are added
const Common: Record<EntryKind, string[]> = {
    user: ['givenName', 'sn', 'displayName', 'mail', 'loginShell', 'description'],
    group: ['description'],
};

// Labels of attributes which have a friendlier name
const Labels: Record<string, string> = {
    cn: 'Full name',
    sn: 'Surname',
    givenname: 'Given name',
    displayname: 'Display name',
    mail: 'Mail',
    homedirectory: 'Home directory',
    loginshell: 'Login shell',
    gidnumber: 'Group ID',
    description: 'Description',
    telephonenumber: 'Telephone',
    gecos: 'GECOS',
};

// attrLabel returns the attribute's label
export function attrLabel(name: string): string {
    return Labels[name.toLowerCase()] ?? name;
}

///////////////////////////////////////////////////////////////////////////////
// ENTRIES

// EntryForm is what an entry's form's inputs set
export interface EntryForm {
    schema: EntrySchema;
    // name is the entry's, which is its RDN's value, such as its uid, and
    // which renames it, when it's changed
    name: string;
    // values are the attributes' values, by name, as text
    values: Record<string, string>;
    // added are attributes which were added to the form
    added: string[];
    // password, typed twice, is only set when a user is created
    password: string;
    confirm: string;
    // allocateGID sets a posixAccount's gidNumber to its uidNumber
    allocateGID: boolean;
    // original is the entry which is edited, which the changes are of
    original?: LdapObject;
}

// EntryFormErrors are what's wrong with the form, by its input, which is
// an attribute's name, or name, or confirm
export type EntryFormErrors = Record<string, string>;

// entryForm returns the form which creates an entry, or edits one, with
// its attributes
export function entryForm(schema: EntrySchema, entry?: LdapObject): EntryForm {
    const form: EntryForm = {
        schema,
        name: entry ? rdnValue(entry.dn) : '',
        values: {},
        added: [],
        password: '',
        confirm: '',
        allocateGID: !entry && isPosix(schema),
        original: entry,
    };
    if (entry) {
        for (const name of [...schema.must, ...schema.may]) {
            if (editable(form, name)) {
                form.values[name] = first(entry, name) ?? '';
            }
        }
    }
    return form;
}

// isPosix returns whether the schema's entries are POSIX accounts, whose
// group ID can be their user ID
export function isPosix(schema: EntrySchema): boolean {
    return schema.kind === 'user' && schemaHasClass(schema, 'posixAccount');
}

// formFields returns the attributes the form shows, in order: those which
// are required, which the server doesn't set, those which are common, those
// an edited entry has, and those which were added
export function formFields(form: EntryForm): string[] {
    const { schema } = form;
    const result: string[] = [];
    const add = (name: string) => {
        if (!result.some((n) => n.toLowerCase() === name.toLowerCase()) && shown(form, name)) {
            result.push(name);
        }
    };
    schema.must.forEach(add);
    const may = new Map(schema.may.map((n) => [n.toLowerCase(), n]));
    for (const name of Common[schema.kind]) {
        const found = may.get(name.toLowerCase());
        if (found) {
            add(found);
        }
    }
    if (form.original) {
        for (const name of schema.may) {
            if (values(form.original, name).length) {
                add(name);
            }
        }
    }

    // Those which are well known are first, in the order people expect,
    // such as a full name before a surname, and those which were added last
    const rank = (name: string) => {
        const i = Order.indexOf(name.toLowerCase());
        return i < 0 ? Order.length : i;
    };
    result.sort((a, b) => rank(a) - rank(b));
    form.added.forEach(add);
    return result;
}

// Order is the order of attributes which are well known
const Order = ['cn', 'givenname', 'sn', 'displayname', 'mail', 'gidnumber', 'homedirectory', 'loginshell', 'description'];

// addable returns the attributes which can be added to the form: those the
// entries may have, which it doesn't show, by name
export function addable(form: EntryForm): string[] {
    const fields = new Set(formFields(form).map((n) => n.toLowerCase()));
    return form.schema.may.filter((n) => !fields.has(n.toLowerCase()) && shown(form, n)).sort((a, b) => a.localeCompare(b));
}

// isRequired returns whether the attribute must have a value
export function isRequired(form: EntryForm, name: string): boolean {
    return form.schema.must.some((n) => n.toLowerCase() === name.toLowerCase());
}

// defaultValue returns what a new entry's required attribute is, when it's
// empty, such as a home directory
export function defaultValue(form: EntryForm, name: string): string | undefined {
    if (!form.original && name.toLowerCase() === 'homedirectory' && form.name.trim()) {
        return `/home/${form.name.trim()}`;
    }
    return undefined;
}

// entryFormErrors returns what's wrong with the form, which isn't sent until
// there's nothing: a name, the required attributes, numbers, a mail address
// with an @, and the password, the same when it's typed again
export function entryFormErrors(form: EntryForm): EntryFormErrors {
    const errors: EntryFormErrors = {};
    if (!form.name.trim()) {
        errors.name = 'A name is required';
    }
    for (const name of formFields(form)) {
        const value = (form.values[name] ?? '').trim();
        if (!value) {
            if (isRequired(form, name) && defaultValue(form, name) === undefined) {
                errors[name] = `${attrLabel(name)} is required`;
            }
        } else if (isInteger(form.schema, name) && !/^-?\d+$/.test(value)) {
            errors[name] = `${attrLabel(name)} is a number`;
        } else if (name.toLowerCase() === 'mail' && !/^[^\s@]+@[^\s@]+$/.test(value)) {
            errors[name] = 'A mail address is a name, an @ and a domain';
        }
    }
    if (!form.original && form.password !== form.confirm) {
        errors.confirm = "It isn't the same password";
    }
    return errors;
}

// entryAttrs returns the attributes the form sets. A new entry has those
// which aren't empty, or their defaults, and its password. An edited entry
// has those which changed, which are deleted when they're emptied, and its
// name, in its RDN's attribute, when it's renamed.
export function entryAttrs(form: EntryForm): Attrs {
    const attrs: Attrs = {};
    for (const name of formFields(form)) {
        const raw = form.values[name] ?? '';
        const value = raw.trim() || (defaultValue(form, name) ?? '');
        if (!form.original) {
            if (value) {
                attrs[name] = [value];
            }
            continue;
        }

        // An attribute which wasn't changed isn't sent, even when it has
        // spaces around it, which the directory keeps
        const original = first(form.original, name) ?? '';
        if (raw !== original && value !== original) {
            attrs[name] = value ? [value] : null;
        }
    }
    if (!form.original) {
        if (form.password) {
            attrs.userPassword = [form.password];
        }
    } else {
        // A rename replaces the name's value, first, as the server renames
        // with it, and keeps the attribute's others
        const name = form.name.trim();
        const old = rdnValue(form.original.dn);
        if (name !== old) {
            const attr = rdnAttr(form.original.dn);
            attrs[attr] = [name, ...values(form.original, attr).filter((v) => v !== old && v !== name)];
        }
    }
    return attrs;
}

///////////////////////////////////////////////////////////////////////////////
// PASSWORDS

// PasswordForm is what the password's form's inputs set: the password,
// typed twice, or none, when it's generated
export interface PasswordForm {
    password: string;
    confirm: string;
    generate: boolean;
}

export type PasswordFormErrors = Partial<Record<'password' | 'confirm', string>>;

// passwordForm returns the form which sets an entry's password, which is
// generated, unless it's typed
export function passwordForm(): PasswordForm {
    return { password: '', confirm: '', generate: true };
}

// passwordFormErrors returns what's wrong with the form: a password, unless
// it's generated, the same when it's typed again
export function passwordFormErrors(form: PasswordForm): PasswordFormErrors {
    const errors: PasswordFormErrors = {};
    if (form.generate) {
        return errors;
    }
    if (!form.password) {
        errors.password = 'A password is required, unless it\'s generated';
    } else if (form.password !== form.confirm) {
        errors.confirm = "It isn't the same password";
    }
    return errors;
}

// passwordRequest is the request which resets the password, as the
// manager, to the one typed, or one it generates
export function passwordRequest(form: PasswordForm): PasswordRequest {
    return form.generate ? {} : { new: form.password };
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// shown returns whether the form shows the attribute: not the name, which
// is its own input, nor those the server sets, nor those which aren't text,
// nor a POSIX group ID which is the user ID, nor, for an edited entry, one
// with more than one value, which an input can't show
function shown(form: EntryForm, name: string): boolean {
    const lower = name.toLowerCase();
    if (lower === namingAttr(form.schema).toLowerCase() || Managed[form.schema.kind].some((n) => n.toLowerCase() === lower)) {
        return false;
    } else if (isBinaryAttr(form.schema, name) || form.schema.types.get(lower)?.noUserModification) {
        return false;
    } else if (lower === 'gidnumber' && form.allocateGID) {
        return false;
    }
    return editable(form, name);
}

// editable returns whether an edited entry's attribute has one value, at
// most
function editable(form: EntryForm, name: string): boolean {
    return !form.original || values(form.original, name).length <= 1;
}

// rdnAttr returns the attribute of the DN's RDN, such as uid
function rdnAttr(dn: string): string {
    const value = rdn(dn);
    const equals = value.indexOf('=');
    return equals < 0 ? value : value.slice(0, equals).trim();
}
