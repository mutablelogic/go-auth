// The client of signing in, which go-auth's auth/httphandler serves, at the
// client's prefix, such as /api. The session is a cookie, which the browser
// keeps, and sends.

import { request, url, type Client } from '@mutablelogic/go-server/api';
import type { Session } from './schema.ts';

// getSession returns who's signed in, or throws an ApiError, which is 401
// when no one is
export async function getSession(client: Client, signal?: AbortSignal): Promise<Session> {
    return request<Session>(client, 'GET', 'auth/session', { signal });
}

// signIn signs in with a password provider, which sets the session's
// cookie, and returns the session, or throws an ApiError, which is 401 when
// the username or password isn't right
export async function signIn(client: Client, provider: string, username: string, password: string): Promise<Session> {
    return request<Session>(client, 'POST', `auth/${encodeURIComponent(provider)}/login`, { body: { username, password } });
}

// signOut ends the session, and clears its cookie
export async function signOut(client: Client): Promise<void> {
    await request<void>(client, 'POST', 'auth/logout');
}

// redirectURL is where a redirect provider is signed in with, which
// returns to the path, once signed in
export function redirectURL(client: Client, provider: string, returnTo: string): string {
    return url(client.base, `auth/${encodeURIComponent(provider)}/login`, { return: returnTo });
}
