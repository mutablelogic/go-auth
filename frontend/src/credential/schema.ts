// The credential API's types, as go-auth's credential package has them

// Credential is a stored credential's key, and when it was last changed,
// when the backend records it, without its value
export interface Credential {
    key: string;
    updated_at?: string;
}

// CredentialList is the stored credentials, in key order
export interface CredentialList {
    count: number;
    body?: Credential[];
}

// CredentialSet is a request which stores a credential, which can be any
// JSON value, replacing any with the key
export interface CredentialSet {
    key: string;
    credentials: unknown;
}

// CredentialFeatures is what the server's credential manager can do, from
// its configuration's credential section: its backend, such as file, and
// whether a value can be read with its passphrase, and rotated
export interface CredentialFeatures {
    backend: string;
    decrypt: boolean;
    rotate: boolean;
}

// KeyPattern is what a key is: a letter, then up to 63 letters, digits,
// underscores and hyphens
export const KeyPattern = /^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/;
