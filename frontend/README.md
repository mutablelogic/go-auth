# Web UI

go-auth's web UI modules, which any app can include, and the auth server's app, which is built from them.

- It's built on [`@mutablelogic/go-server`](https://github.com/mutablelogic/go-server/tree/main/frontend), from GitHub Packages, with Lit and Carbon's web components.
- An app is composed of **modules**. Each owns an item in the menu bar, and the sidebar while it's active: Credentials, and Certificates.

## Modules

| Import | What it has |
|---|---|
| `@mutablelogic/go-auth/credential` | The credential API's types and client, the form which stores a credential, and `CredentialController`, which keeps the credentials in a go-server `ListController` |
| `@mutablelogic/go-auth/credential/view` | `ga-credentials`, a Credentials page; `credentialModule`, which adds it to an app; and its parts, `credentialColumns`, `credentialFormView`, `passphraseFormView` and `valueView` |
| `@mutablelogic/go-auth/cert` | The certificate API's types and client, the forms which create and renew certificates, PEM encoding, and `CertController`, which keeps the certificates in a go-server `ListController` |
| `@mutablelogic/go-auth/cert/view` | `ga-certificates`, a page of certificate authorities or leaf certificates; `certModule`, which adds both pages to an app; and its parts, `authorityColumns`, `certificateColumns`, `certDetailsView`, `certFormView` and `renewFormView` |

Including Credentials in another app:

```ts
import { credentialModule } from '@mutablelogic/go-auth/credential/view';

credentialModule({ nav, router, client, root: document.querySelector('main')!, notifications, changes });
```

- **The module:** adds the Credentials section to the app's `NavController`, its page to `root`, and its route to the `Router`.
- **The page:** `ga-credentials` has its own header, which stores a credential, and, for AWS and Bitwarden, refreshes the list, since their changes made elsewhere aren't published. It has a table of the credentials, and a panel. The panel gets a credential's value with its passphrase, replaces it, rotates it, and deletes it.
- **Values:** only shown with the passphrase they were encrypted with, so only for the file and pg backends.
- **Parts:** an app with its own table and panel can use `CredentialController`, `credentialColumns` and the form views instead.
- **Certificates:** `certModule` adds a Certificates section the same way, with two pages, Leaf Certificates and Certificate Authorities. A CA's panel creates a certificate it signs, on the Leaf Certificates page. Its panel downloads a certificate, with its chain, and a leaf certificate's private key, as PEM. It also renews a certificate, enables or disables it, and changes its tags. The header creates certificate authorities and certificates.
- **Configuration:** the auth server's app includes Certificates only when `/config.json` has a `cert` section, which a server built with certificates registers. Its `root` says whether a root is stored, without which certificate authorities can't be created.

## Layout

| Folder | What it has |
|---|---|
| `src/credential` | The Credentials module, which `npm run build` builds into `dist` |
| `app` | The auth server's app: `index.html`, the shell, and `index.ts`, which adds the modules, which `npm run build-app` builds into `app/dist` |
| `embed.go` | Embeds `app/dist`, with the `frontend` tag |
| `cmd` | Serves the app, and `/config.json`, behind the `frontend` tag |

## Developing

| Command | Description |
|---|---|
| `make frontend` | Installs from `package-lock.json`, type checks, and builds the modules and the app |
| `make frontend-test` | Type checks, and runs the tests |
| `make` | Builds the UI, and then the commands, which embed it |

- **Token:** installing needs a token which can read GitHub Packages, in `GITHUB_TOKEN`, such as `$(gh auth token)`.
- **Node:** 22.18 or later.
