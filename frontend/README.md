# Web UI

go-auth's web UI modules, which any app can include, and the auth server's app, which is built from them.

- It's built on [`@mutablelogic/go-server`](https://github.com/mutablelogic/go-server/tree/main/frontend), from GitHub Packages, with Lit and Carbon's web components.
- An app is composed of **modules**. Each owns an item in the menu bar, and the sidebar while it's active: Credentials, Certificates and LDAP.

## Modules

| Import | What it has |
|---|---|
| `@mutablelogic/go-auth/credential` | The credential API's types and client, the form which stores a credential, and `CredentialController`, which keeps the credentials in a go-server `ListController` |
| `@mutablelogic/go-auth/credential/view` | `ga-credentials`, a Credentials page; `credentialModule`, which adds it to an app; and its parts, `credentialColumns`, `credentialFormView`, `passphraseFormView` and `valueView` |
| `@mutablelogic/go-auth/cert` | The certificate API's types and client, the forms which create and renew certificates, PEM encoding, and `CertController` and `SubjectController`, which keep the certificates and subjects in a go-server `ListController` |
| `@mutablelogic/go-auth/cert/view` | `ga-certificates`, a page of certificate authorities or leaf certificates; `ga-subjects`, a page of subjects; `certModule`, which adds both pages to an app; and its parts, `authorityColumns`, `certificateColumns`, `certDetailsView`, `certFormView` and `renewFormView` |
| `@mutablelogic/go-auth/ldap` | The LDAP API's types and client, DN, attribute and filter helpers, the entry and password forms, `loadEntrySchemas`, `listAll` and `listAllGroups`, and `LdapStatusController`, `UserController`, `GroupController`, `ObjectController` and `SchemaController` |
| `@mutablelogic/go-auth/ldap/view` | `ga-ldap-users`, the Users page; `LdapPage`, the pages' base, with the connection's status in their header; `ldapModule`, which adds the LDAP pages to an app; and its parts, `userColumns`, `entryFormView`, `passwordFormView`, `attrsView` and `secretView` |

Including Credentials in another app:

```ts
import { credentialModule } from '@mutablelogic/go-auth/credential/view';

credentialModule({ nav, router, client, root: document.querySelector('main')!, notifications, changes });
```

- **The module:** adds the Credentials section to the app's `NavController`, its page to `root`, and its route to the `Router`.
- **The page:** `ga-credentials` has its own header, which stores a credential, and, for AWS and Bitwarden, refreshes the list, since their changes made elsewhere aren't published. It has a table of the credentials, and a panel. The panel gets a credential's value with its passphrase, replaces it, rotates it, and deletes it.
- **Values:** only shown with the passphrase they were encrypted with, so only for the file and pg backends.
- **Parts:** an app with its own table and panel can use `CredentialController`, `credentialColumns` and the form views instead.
- **Certificates:** `certModule` adds a Certificates section the same way, with three pages, Leaf Certificates, Certificate Authorities and Subjects. A CA's panel creates a certificate it signs, on the Leaf Certificates page. Its panel downloads a certificate, with its chain, and a leaf certificate's private key, as PEM. It also renews a certificate, enables or disables it, and changes its tags.
- **Versions:** the certificate pages list each certificate's latest version, which alone is renewed, or signs certificates. A row expands to its older versions, which open in the panel, where they can be enabled or disabled, retagged, and downloaded.
- **Tags column:** a certificate's state comes first, in colour: Valid, Expired or Not yet valid, and Disabled. Its tags, with those it inherits, follow in gray.
- **Sorting:** the certificate tables sort by Name, Signer and Expires, on the server, when their headers are clicked.
- **Toolbar:** each certificate table has a search, of the certificates' names, and a settings menu, whose Show disabled lists disabled certificates, and their disabled older versions, which are hidden otherwise.
- **Create:** each table's toolbar ends with its Create button: a certificate, a certificate authority, or a subject. Create a certificate authority is disabled without a root.
- **Subjects:** the Subjects page lists the subjects, with how many certificates use each. It edits or deletes one which no certificate uses.
- **Configuration:** the auth server's app includes Certificates only when `/config.json` has a `cert` section, which a server built with certificates registers. Its `root` says whether a root is stored, without which certificate authorities can't be created.
- **LDAP:** `ldapModule` adds an LDAP section, with Users and Groups, when the server has their DNs, Objects and Schema. Each page's header shows Connected or Disconnected, with the host and user, from the `ldap` section of `/config.json`, and then the connection's changes. The app includes it only when `/config.json` has that section.
- **Users:** a table of users, searched by name, full name, mail and surname. A user's panel shows its groups and attributes. It adds the user to a group, or removes it from one, sets its password, or generates one, which is shown once, edits it, and deletes it.
- **Entry forms:** a new user's form is made from the classes users are created with (`ldap/class?for=user`), and an existing user's from its own classes, with those they inherit from: what they must have is required, what's common is offered, and Add an attribute adds any other they may have. Attributes the server sets, such as the name, `uidNumber`, and a POSIX group ID which is the user ID, aren't shown. An empty home directory is `/home/` and the name.

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
