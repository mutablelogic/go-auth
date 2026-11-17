// go-auth's sign-in, as a Lit element, of Carbon's web components:
//
// - ga-session is who's signed in, with a button which signs out, and goes
//   to the sign-in page.
// - ga-sign-in signs in with the providers: a button for each redirect
//   provider, such as Google, which signs in at its page, and a username
//   and password for each password provider, such as LDAP. Once signed in,
//   it goes to the path to return to.
//
// It needs lit, @carbon/web-components and @mutablelogic/go-server, which
// are the package's peer dependencies.

import { LitElement, html, nothing, type TemplateResult } from 'lit';
import { live } from 'lit/directives/live.js';
import { ApiError, type Client } from '@mutablelogic/go-server/api';
import { redirectURL, signIn, signOut } from './httpclient.ts';
import { localPath, signInURL } from './index.ts';
import type { ProviderMeta, Session } from './schema.ts';

// Carbon's elements
import '@carbon/web-components/es/components/button/index.js';
import '@carbon/web-components/es/components/notification/index.js';
import '@carbon/web-components/es/components/password-input/index.js';
import '@carbon/web-components/es/components/text-input/index.js';

///////////////////////////////////////////////////////////////////////////////
// ELEMENTS

// SignInElement signs in with the providers, and goes to the path to return to
export const SignInTag = 'ga-sign-in';

export class SignInElement extends LitElement {
    static override properties = {
        client: { attribute: false },
        providers: { attribute: false },
        returnTo: { attribute: 'return' },
        busy: { state: true },
        error: { state: true },
    };

    // The API's client, the providers, and the path to return to
    declare client?: Client;
    declare providers: ProviderMeta[];
    declare returnTo: string;

    // Whether it's signing in, and why it couldn't, by the provider
    declare busy: string;
    declare error: Record<string, string>;

    // The usernames and passwords, by the provider
    private credentials: Record<string, { username: string; password: string }> = {};

    constructor() {
        super();
        this.providers = [];
        this.returnTo = '/';
        this.busy = '';
        this.error = {};
    }

    // It's in the light DOM, so Carbon's theme applies
    protected override createRenderRoot() {
        return this;
    }

    override render(): TemplateResult {
        const redirects = this.providers.filter((p) => p.kind === 'redirect');
        const passwords = this.providers.filter((p) => p.kind === 'password');
        return html`
            <div class="ga-sign-in">
                <h1>Sign in</h1>
                ${this.providers.length === 0 ? html`<p>There's nothing to sign in with: the server has no providers.</p>` : nothing}
                ${passwords.map((p) => this.passwordView(p, passwords.length > 1))}
                ${redirects.length > 0 && passwords.length > 0 ? html`<p class="ga-sign-in-or">or</p>` : nothing}
                ${redirects.map((p) => this.redirectView(p))}
            </div>`;
    }

    // redirectView is a button which signs in at the provider's page
    private redirectView(p: ProviderMeta): TemplateResult | typeof nothing {
        if (!this.client) {
            return nothing;
        }
        return html`
            <cds-button kind="tertiary" size="lg" href=${redirectURL(this.client, p.name, localPath(this.returnTo))}>
                Sign in with ${p.label}
            </cds-button>`;
    }

    // passwordView is a username and password, for the provider
    private passwordView(p: ProviderMeta, labelled: boolean): TemplateResult {
        const credential = this.credentials[p.name] ??= { username: '', password: '' };
        const submit = () => void this.submit(p);
        const enter = (event: KeyboardEvent) => {
            if (event.key === 'Enter') {
                submit();
            }
        };
        return html`
            <form class="ga-sign-in-form" @submit=${(event: Event) => { event.preventDefault(); submit(); }}>
                ${labelled ? html`<h2>${p.label}</h2>` : nothing}
                ${this.error[p.name] ? html`
                    <cds-inline-notification kind="error" title="Not signed in" subtitle=${this.error[p.name]} hide-close-button></cds-inline-notification>` : nothing}
                <cds-text-input label="Username" autocomplete="username" .value=${live(credential.username)}
                    @input=${(event: Event) => { credential.username = (event.target as HTMLInputElement).value; }}
                    @keydown=${enter}></cds-text-input>
                <cds-password-input label="Password" autocomplete="current-password" .value=${live(credential.password)}
                    @input=${(event: Event) => { credential.password = (event.target as HTMLInputElement).value; }}
                    @keydown=${enter}></cds-password-input>
                <cds-button size="lg" ?disabled=${this.busy !== ''} @click=${submit}>
                    ${this.busy === p.name ? 'Signing in…' : labelled ? `Sign in with ${p.label}` : 'Sign in'}
                </cds-button>
            </form>`;
    }

    // submit signs in with the provider's username and password, and goes to
    // the path to return to
    private async submit(p: ProviderMeta): Promise<void> {
        const credential = this.credentials[p.name];
        if (!this.client || this.busy || !credential) {
            return;
        } else if (!credential.username || !credential.password) {
            this.error = { ...this.error, [p.name]: 'A username and password are needed' };
            return;
        }
        this.busy = p.name;
        this.error = { ...this.error, [p.name]: '' };
        try {
            await signIn(this.client, p.name, credential.username, credential.password);
            window.location.assign(localPath(this.returnTo));
        } catch (error) {
            credential.password = '';
            this.error = { ...this.error, [p.name]: reason(error) };
        } finally {
            this.busy = '';
        }
    }
}

// SessionElement is who's signed in, with a button which signs out, or a
// button which signs in, when no one is, and it's signed out
export const SessionTag = 'ga-session';

export class SessionElement extends LitElement {
    static override properties = {
        client: { attribute: false },
        session: { attribute: false },
        signedOut: { attribute: false },
        busy: { state: true },
    };

    // The API's client, and the session, or whether no one's signed in,
    // when the APIs don't need a session
    declare client?: Client;
    declare session?: Session;
    declare signedOut: boolean;
    declare busy: boolean;

    constructor() {
        super();
        this.signedOut = false;
        this.busy = false;
    }

    // It's in the light DOM, so Carbon's theme applies
    protected override createRenderRoot() {
        return this;
    }

    override render(): TemplateResult | typeof nothing {
        const session = this.session;
        if (!session) {
            return this.signedOut ? html`
                <div class="ga-session">
                    <cds-button kind="ghost" size="sm" href=${signInURL(window.location.pathname + window.location.search + window.location.hash)}>Sign in</cds-button>
                </div>` : nothing;
        }
        const who = session.user.name || session.user.email || session.user.id;
        return html`
            <div class="ga-session">
                <span class="ga-session-user" title=${session.user.email ?? who}>${who}</span>
                <cds-button kind="ghost" size="sm" ?disabled=${this.busy} @click=${() => void this.signOut()}>Sign out</cds-button>
            </div>`;
    }

    // signOut ends the session, and goes to the sign-in page, which it
    // does when the session has already ended
    private async signOut(): Promise<void> {
        if (!this.client || this.busy) {
            return;
        }
        this.busy = true;
        try {
            await signOut(this.client);
        } catch (error) {
            if (!(error instanceof ApiError && error.status === 401)) {
                this.busy = false;
                throw error;
            }
        }
        window.location.assign(signInURL('/'));
    }
}

// reason is why signing in failed, to show
function reason(error: unknown): string {
    if (error instanceof ApiError && error.status === 401) {
        return "The username or password isn't right";
    }
    return error instanceof Error ? error.message : String(error);
}

if (!customElements.get(SignInTag)) {
    customElements.define(SignInTag, SignInElement);
}
if (!customElements.get(SessionTag)) {
    customElements.define(SessionTag, SessionElement);
}

declare global {
    interface HTMLElementTagNameMap {
        'ga-sign-in': SignInElement;
        'ga-session': SessionElement;
    }
}
