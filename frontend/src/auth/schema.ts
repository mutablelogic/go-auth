// The types of signing in, as go-auth's auth/schema has them: the
// providers, which the configuration's auth section lists, and a session

// ProviderKind is how a provider is signed in with: at its own page, which
// it redirects back from, or with a username and password
export type ProviderKind = 'redirect' | 'password';

// ProviderMeta is a provider, which is in its paths, by its name
export interface ProviderMeta {
    name: string;
    label: string;
    kind: ProviderKind;
}

// AuthConfig is the configuration's auth section: the providers which can
// be signed in with
export interface AuthConfig {
    providers: ProviderMeta[];
}

// User is who signed in
export interface User {
    id: string;
    name?: string;
    email?: string;
    groups?: string[];
}

// Session is a user's, once they've signed in, with their scopes
export interface Session {
    id: string;
    user: User;
    provider: string;
    client?: string;
    scopes?: string[];
    created_at: string;
    expires_at: string;
}
