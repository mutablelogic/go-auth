// The auth server's sign-in page, which signs in with the providers which
// the configuration's auth section lists, and returns to the path its
// return parameter says, once signed in, such as the app, or the
// authorization of an OAuth client.

import '@carbon/styles/css/styles.min.css';
import './fonts.css';

import { configClient, configSection, getConfig } from '@mutablelogic/go-server/config';
import { localPath, type AuthConfig } from '../src/auth/index.ts';
import '../src/auth/view.ts';

const view = document.querySelector('ga-sign-in');
const read = await getConfig().catch(() => undefined);
if (view) {
    view.client = configClient(read ?? { prefix: '/api' });
    view.providers = configSection<AuthConfig>(read, 'auth')?.providers ?? [];
    view.returnTo = localPath(new URLSearchParams(window.location.search).get('return'));
}
