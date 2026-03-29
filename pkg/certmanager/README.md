# pkg/certmanager

`certmanager` stores and manages certificate chains, starting from a root certificate and continuing through intermediate certificate authorities to usable end-entity certificates. The intended model is a chain such as `root => CA => usable cert`, with the private key material stored in PostgreSQL under passphrase-based encryption.

## Storage passphrases

`certmanager` uses storage passphrases to encrypt private key material before it is written to PostgreSQL. These are separate from any passphrase used to protect the PEM file on disk. Storage passphrases are versioned in the order they are supplied. The first passphrase is version `1`, the second is version `2`, and so on. It's possible to rotate the encrypted private keys between passphrase versions through the CLI.

Each storage passphrase must be at least 8 characters long. It's recommended to set these passphrases as environment variables to avoid exposing them in command history or process lists. Use `certmanager bootstrap --help` to determine the correct environment variable to use.

## Bootstrapping

### Generating a root certificate

Export the source-key passphrase and generate an encrypted RSA private key in the traditional PEM format expected by the current importer:

```bash
openssl genrsa -traditional -aes256 -out root.key.pem 4096
```

This will prompt for a passphrase to encrypt the private key. You can also specify the passphrase non-interactively with the `-passout` flag, but be cautious about exposing passphrases in command history or process lists. Generate a self-signed root certificate from that key:

```bash
export ROOTKEY_PASSPHRASE='<passphrase>'
openssl req \
  -x509 \
  -new \
  -key root.key.pem \
  -passin env:ROOTKEY_PASSPHRASE \
  -sha256 \
  -days 3650 \
  -out root.crt.pem \
  -subj "/CN=Example Root CA/O=Example Org"
cat root.crt.pem root.key.pem > root.bundle.pem  
```

### Importing the root certificate into the database

Import the PEM bundle with the bootstrap command:

```bash
export STORAGE_PASSPHRASE='<passphrase>'

certmanager bootstrap \
  --pg.url="postgres://user:password@localhost/authdb" \
  --certificate-pem root.bundle.pem \
  --certificate-passphrase "${ROOTKEY_PASSPHRASE}" \
  --storage-passphrase "${STORAGE_PASSPHRASE}"

unset ROOTKEY_PASSPHRASE
unset STORAGE_PASSPHRASE
```

If `root.bundle.pem` contains an unencrypted private key without passphrase,
the import can omit `--certificate-passphrase`.
Once you have the PEM bundle, you could delete the source key and certificate files from disk.
