// The forms which create a certificate authority or a certificate, renew
// one, and change a certificate's tags

import { Day, NamePattern, type CertMeta, type CreateCertRequest, type RenewCertRequest, type SubjectMeta } from './schema.ts';

// SubjectFields are a subject's inputs, by its JSON field
export const SubjectFields: readonly { field: keyof SubjectMeta; label: string }[] = [
    { field: 'organizationName', label: 'Organization' },
    { field: 'organizationalUnit', label: 'Organizational unit' },
    { field: 'countryName', label: 'Country' },
    { field: 'stateOrProvinceName', label: 'State or province' },
    { field: 'localityName', label: 'City' },
    { field: 'streetAddress', label: 'Street address' },
    { field: 'postalCode', label: 'Postal code' },
];

// CertForm is what the create form's inputs set: a certificate authority,
// or a leaf certificate, which a CA signs, and which can have SAN entries.
// Lists are separated by commas, spaces or lines, and the expiry is in days.
export interface CertForm {
    ca: boolean;
    name: string;
    signer: string;
    expiry: string;
    san: string;
    tags: string;
    subject: SubjectMeta;
}

// RenewForm is what the renew form's inputs set: the expiry in days, which
// is the current lifetime when it's empty, and the subject, whose fields
// are kept when they're empty
export interface RenewForm {
    expiry: string;
    subject: SubjectMeta;
}

// CertFormErrors are what's wrong with a form, by its input
export type CertFormErrors = Partial<Record<'name' | 'signer' | 'expiry' | 'san' | 'tags', string>>;

// certForm returns the form which creates a certificate authority, or a
// certificate signed by the CA, when it's set
export function certForm(ca: boolean, signer = ''): CertForm {
    return { ca, name: '', signer, expiry: '', san: '', tags: '', subject: {} };
}

// renewForm returns the form which renews a certificate
export function renewForm(): RenewForm {
    return { expiry: '', subject: {} };
}

// certFormErrors returns what's wrong with the form, which isn't sent until
// there's nothing
export function certFormErrors(form: CertForm): CertFormErrors {
    const errors: CertFormErrors = {};
    const name = form.name.trim();
    if (!name) {
        errors.name = 'A name is required';
    } else if (!NamePattern.test(name)) {
        errors.name = 'A name starts with a letter, then has up to 63 letters, digits, _ and -';
    }
    if (!form.ca && !form.signer.trim()) {
        errors.signer = 'A certificate authority is required';
    }
    const expiry = expiryError(form.expiry);
    if (expiry) {
        errors.expiry = expiry;
    }
    const tags = splitList(form.tags).filter((tag) => !NamePattern.test(tag));
    if (tags.length) {
        errors.tags = `A tag starts with a letter, then has letters, digits, _ and -, which ${tags.join(', ')} doesn't`;
    }
    if (form.ca && splitList(form.san).length) {
        errors.san = "A certificate authority doesn't have SAN entries";
    }
    return errors;
}

// renewFormErrors returns what's wrong with the renew form
export function renewFormErrors(form: RenewForm): CertFormErrors {
    const expiry = expiryError(form.expiry);
    return expiry ? { expiry } : {};
}

// certRequest returns the request of the create form
export function certRequest(form: CertForm): CreateCertRequest {
    const req: CreateCertRequest = { name: form.name.trim() };
    const expiry = expiryNanoseconds(form.expiry);
    if (expiry) {
        req.expiry = expiry;
    }
    const subject = subjectOf(form.subject);
    if (subject) {
        req.subject = subject;
    }
    const san = splitList(form.san);
    if (san.length && !form.ca) {
        req.san = san;
    }
    const tags = splitList(form.tags);
    if (tags.length) {
        req.tags = tags;
    }
    return req;
}

// renewRequest returns the request of the renew form
export function renewRequest(form: RenewForm): RenewCertRequest {
    const req: RenewCertRequest = {};
    const expiry = expiryNanoseconds(form.expiry);
    if (expiry) {
        req.expiry = expiry;
    }
    const subject = subjectOf(form.subject);
    if (subject) {
        req.subject = subject;
    }
    return req;
}

// tagsRequest returns the change of a certificate's tags, which are removed
// when the list is empty
export function tagsRequest(tags: string): CertMeta {
    return { tags: splitList(tags) };
}

// tagsError returns what's wrong with a list of tags
export function tagsError(tags: string): string | undefined {
    const invalid = splitList(tags).filter((tag) => !NamePattern.test(tag));
    return invalid.length ? `A tag starts with a letter, then has letters, digits, _ and -, which ${invalid.join(', ')} doesn't` : undefined;
}

// splitList splits a list separated by commas, spaces or lines, without
// empty or repeated entries
export function splitList(value: string): string[] {
    return [...new Set(value.split(/[\s,]+/).map((entry) => entry.trim()).filter(Boolean))];
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// expiryError returns what's wrong with an expiry in days, which can be
// empty
function expiryError(expiry: string): string | undefined {
    if (expiry.trim() === '') {
        return undefined;
    }
    const days = Number(expiry);
    return Number.isInteger(days) && days > 0 ? undefined : 'The expiry is a number of days';
}

// expiryNanoseconds returns an expiry in days in nanoseconds, or undefined
// when it's empty
function expiryNanoseconds(expiry: string): number | undefined {
    const days = Number(expiry);
    return expiry.trim() !== '' && Number.isInteger(days) && days > 0 ? days * Day : undefined;
}

// subjectOf returns the subject's fields which are set, trimmed, or
// undefined when none are
function subjectOf(subject: SubjectMeta): SubjectMeta | undefined {
    const result: SubjectMeta = {};
    for (const { field } of SubjectFields) {
        const value = subject[field]?.trim();
        if (value) {
            result[field] = value;
        }
    }
    return Object.keys(result).length ? result : undefined;
}
