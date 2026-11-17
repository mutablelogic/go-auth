// The auth server's web UI, which is composed of modules, each of which
// owns an item in the menu bar, and the sidebar while it's active:
// Credentials, which the server always has, and Certificates and LDAP, when
// it has them, which its configuration's cert and ldap sections say. Another
// app includes a module the same way, from @mutablelogic/go-auth/credential/view,
// cert/view or ldap/view.

import '@carbon/styles/css/styles.min.css';
import './fonts.css';

// go-server's components
import { ApiError } from '@mutablelogic/go-server/api';
import { ChangesController } from '@mutablelogic/go-server/broadcaster';
import { ConfigController, configClient, configSection, getConfig } from '@mutablelogic/go-server/config';
import '@mutablelogic/go-server/config/view';
import { NavController } from '@mutablelogic/go-server/nav';
import '@mutablelogic/go-server/nav/view';
import { NotificationController } from '@mutablelogic/go-server/notification';
import '@mutablelogic/go-server/notification/view';
import { Router } from '@mutablelogic/go-server/router';

// go-auth's modules
import { getSession, signInURL, type AuthConfig } from '../src/auth/index.ts';
import '../src/auth/view.ts';
import type { CertFeatures } from '../src/cert/schema.ts';
import { certModule } from '../src/cert/view.ts';
import type { CredentialFeatures } from '../src/credential/schema.ts';
import { credentialModule } from '../src/credential/view.ts';
import type { LdapStatus } from '../src/ldap/schema.ts';
import { ldapModule } from '../src/ldap/view.ts';

// Errors, and the server's status, are shown as toasts
const notifications = new NotificationController();
const notificationsView = document.querySelector('gs-notifications');
if (notificationsView) {
    notificationsView.controller = notifications;
}

// The configuration says where the API is, and the changes, which the
// server's status follows
const read = await getConfig().catch((error) => {
    notifications.error("The configuration couldn't be read", error);
    return undefined;
});
const client = configClient(read ?? { prefix: '/api' });

// When the server has sign-in, who's signed in. When its APIs need a
// session, those who aren't signed in do, and return here, or else they
// can, from the sidebar.
// Without it, the APIs aren't authenticated.
const auth = configSection<AuthConfig>(read, 'auth');
if (auth) {
    let signedOut = false;
    const session = await getSession(client).catch((error) => {
        if (error instanceof ApiError && error.status === 401) {
            if (auth.required) {
                window.location.replace(signInURL(window.location.pathname + window.location.search + window.location.hash));
                return new Promise<never>(() => {});
            }
            signedOut = true;
            return undefined;
        }
        notifications.error("The session couldn't be read", error);
        return undefined;
    });
    const view = document.querySelector('ga-session');
    if (view) {
        view.client = client;
        view.session = session;
        view.signedOut = signedOut;
    }
}
const changes = new ChangesController(client).onError((error) => notifications.error("Changes couldn't be watched", error));
const server = new ConfigController(changes, { config: read, notifications });
const status = document.querySelector('gs-server-status');
if (status) {
    status.controller = server;
    status.repository = 'https://github.com/mutablelogic/go-auth';
}

// The navigation, of the modules' sections, and the router of their pages
const nav = new NavController({ name: 'auth', prefix: 'go', href: '#', pages: [] });
const header = document.querySelector('gs-header');
const sideNav = document.querySelector('gs-side-nav');
if (header && sideNav) {
    header.controller = nav;
    sideNav.controller = nav;
}
const router = new Router('credentials');
const root = document.querySelector('main')!;

// The modules, which only offer what the server's modules can do
const app = { nav, router, client, root, notifications, changes };
credentialModule({ ...app, features: configSection<CredentialFeatures>(read, 'credential') });
const certs = configSection<CertFeatures>(read, 'cert');
if (certs) {
    certModule({ ...app, features: certs });
}
const ldap = configSection<LdapStatus>(read, 'ldap');
if (ldap) {
    ldapModule({ ...app, status: ldap });
}

// Show the page of the location's hash, and follow the server
router.onRoute((route) => {
    window.scrollTo(0, 0);
    nav.setActive(route.page);
}).start();
changes.start();
