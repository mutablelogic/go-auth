// The form which stores a credential: its key, which can't be changed when
// it replaces a credential, and its value, which is text, or, when json is
// set, JSON, such as an object of a user and a password

import { KeyPattern, type CredentialSet } from './schema.ts';

// CredentialForm is what the form's inputs set
export interface CredentialForm {
    key: string;
    value: string;
    json: boolean;
    // replace is true when it replaces a credential, whose key is fixed
    replace: boolean;
}

// CredentialFormErrors are what's wrong with the form, by its input
export type CredentialFormErrors = Partial<Record<'key' | 'value', string>>;

// credentialForm returns the form which stores a new credential, or
// replaces the value of the one with the key
export function credentialForm(key?: string): CredentialForm {
    return { key: key ?? '', value: '', json: false, replace: key !== undefined };
}

// credentialFormErrors returns what's wrong with the form, which isn't sent
// until there's nothing: a key, which is an identifier, and a value, which
// is JSON when json is set
export function credentialFormErrors(form: CredentialForm): CredentialFormErrors {
    const errors: CredentialFormErrors = {};
    const key = form.key.trim();
    if (!key) {
        errors.key = 'A key is required';
    } else if (!KeyPattern.test(key)) {
        errors.key = 'A key starts with a letter, then has up to 63 letters, digits, _ and -';
    }
    if (form.value === '') {
        errors.value = 'A value is required';
    } else if (form.json) {
        try {
            JSON.parse(form.value);
        } catch {
            errors.value = "The value isn't JSON";
        }
    }
    return errors;
}

// credentialRequest returns the request of the form, whose value is the
// text, or the JSON, when json is set
export function credentialRequest(form: CredentialForm): CredentialSet {
    return {
        key: form.key.trim(),
        credentials: form.json ? JSON.parse(form.value) : form.value,
    };
}
