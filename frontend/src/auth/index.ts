// Signing in to go-auth: the providers, and the session, its client, and
// where to return to, once signed in

export * from './schema.ts';
export * from './httpclient.ts';

// signInPath is the path of the sign-in page, which the server's app
// serves, and authorizing an OAuth client sends people to
export const signInPath = '/login.html';

// localPath returns the path to return to, once signed in, when it's a
// path on this server, which starts with one slash, or else /, so signing
// in never sends anyone to another site
export function localPath(path: string | null | undefined): string {
    if (!path || !path.startsWith('/') || path.startsWith('//') || path.startsWith('/\\') || /[\r\n\\]/.test(path)) {
        return '/';
    }
    try {
        const u = new URL(path, 'http://localhost');
        return u.origin === 'http://localhost' ? path : '/';
    } catch {
        return '/';
    }
}

// signInURL is the sign-in page, which returns to the path, once signed in
export function signInURL(returnTo: string): string {
    return `${signInPath}?${new URLSearchParams({ return: localPath(returnTo) })}`;
}
