// The form which stores a credential, or edits one: its key, which can't be
// changed when it edits one, its description, and its value, which is
// text, typed twice, or, when json is set, JSON, such as an object of a user
// and a password. When it edits one, the value is kept when it's empty, so
// the description can be changed alone.

import { KeyPattern, type Credential, type CredentialSet } from './schema.ts';

// CredentialForm is what the form's inputs set
export interface CredentialForm {
    key: string;
    value: string;
    // confirm is the value again, which must be the same, when it's text
    confirm: string;
    description: string;
    json: boolean;
    // replace is true when it edits a credential, whose key is fixed, and
    // whose value is kept, when it's empty
    replace: boolean;
    // original is the edited credential's description, to know whether it
    // changed
    original: string;
}

// CredentialChange is what the form changes: the value, and its
// description, the description alone, or nothing
export type CredentialChange = 'value' | 'description' | 'none';

// CredentialFormErrors are what's wrong with the form, by its input
export type CredentialFormErrors = Partial<Record<'key' | 'value' | 'confirm', string>>;

// credentialForm returns the form which stores a new credential, or
// replaces the value of the credential, and keeps its description, which
// can be changed
export function credentialForm(credential?: Credential): CredentialForm {
    return {
        key: credential?.key ?? '',
        value: '',
        confirm: '',
        description: credential?.description ?? '',
        json: false,
        replace: credential !== undefined,
        original: credential?.description ?? '',
    };
}

// credentialFormErrors returns what's wrong with the form, which isn't sent
// until there's nothing: a key, which is an identifier, and a value, unless
// it edits a credential, which keeps it, which is JSON, when json is set, or
// else the same when it's typed again
export function credentialFormErrors(form: CredentialForm): CredentialFormErrors {
    const errors: CredentialFormErrors = {};
    const key = form.key.trim();
    if (!key) {
        errors.key = 'A key is required';
    } else if (!KeyPattern.test(key)) {
        errors.key = 'A key starts with a letter, then has up to 63 letters, digits, _ and -';
    }
    if (form.value === '') {
        if (!form.replace) {
            errors.value = 'A value is required';
        } else if (!form.json && form.confirm !== '') {
            errors.confirm = "The values aren't the same";
        }
    } else if (form.json) {
        try {
            JSON.parse(form.value);
        } catch {
            errors.value = "The value isn't JSON";
        }
    } else if (form.confirm !== form.value) {
        errors.confirm = "The values aren't the same";
    }
    return errors;
}

// credentialChange returns what the form changes: the value, with its
// description, when it has one, the description alone, when it edits a
// credential whose value is kept, or nothing
export function credentialChange(form: CredentialForm): CredentialChange {
    if (form.value !== '') {
        return 'value';
    }
    return form.replace && form.description.trim() !== form.original.trim() ? 'description' : 'none';
}

// credentialRequest returns the request of the form, whose value is the
// text, or the JSON, when json is set, with its description, which is
// removed when it's empty
export function credentialRequest(form: CredentialForm): CredentialSet {
    return {
        key: form.key.trim(),
        credentials: form.json ? JSON.parse(form.value) : form.value,
        description: form.description.trim(),
    };
}
