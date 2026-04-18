package main

import (
	"crypto/rsa"
	"fmt"
	"net/url"
	"os"
	"strings"

	// Packages
	autherr "github.com/mutablelogic/go-auth"
	auth "github.com/mutablelogic/go-auth/auth/manager"
	crypto "github.com/mutablelogic/go-auth/crypto"
	server "github.com/mutablelogic/go-server"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type AuthFlags struct {
	Enabled bool       `help:"Enable the authentication manager" env:"AUTH_ENABLED" default:"true" negatable:""`
	Schema  string     `help:"Database schema to use for authentication manager tables" env:"AUTH_SCHEMA"`
	Issuer  *url.URL   `help:"Issuer URL to use in OIDC metadata and tokens. If not set, the server's base URL will be used." env:"AUTH_ISSUER"`
	Signer  []*url.URL `help:"Private Key PEM files to use for signing tokens. Can be specified multiple times for multiple signers."`
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	signerKey = "auth.signer"
	signerKid = "auth-kid"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (flags *AuthFlags) Options(ctx server.Cmd) ([]auth.Opt, *rsa.PrivateKey, error) {
	opts := []auth.Opt{
		auth.WithTracer(ctx.Tracer()),
	}

	// Enabled
	if !flags.Enabled {
		return nil, nil, nil
	}

	// Database schema
	if schema := strings.TrimSpace(flags.Schema); schema != "" {
		opts = append(opts, auth.WithSchema(schema))
	}

	// Issuer
	if flags.Issuer != nil {
		opts = append(opts, auth.WithIssuer(flags.Issuer.String()))
	} else if endpoint, _, err := ctx.ClientEndpoint(); err != nil {
		return nil, nil, err
	} else if issuer, err := url.Parse(endpoint); err != nil {
		return nil, nil, err
	} else {
		flags.Issuer = issuer
		opts = append(opts, auth.WithIssuer(issuer.String()))
	}

	// Signers
	var pk *rsa.PrivateKey
	if len(flags.Signer) == 0 {
		// Convert PEM to RSA private key
		if signer, err := defaultKeyPEM(ctx); err != nil {
			return nil, nil, err
		} else if key, err := crypto.ParsePrivateKeyPEM([]byte(signer), ""); err != nil {
			return nil, nil, err
		} else {
			opts = append(opts, auth.WithSigner(signerKid, key))
			pk = key
		}
	} else {
		for i, signer := range flags.Signer {
			kid, pem, passphrase, err := keyPEM(i, signer)
			if err != nil {
				return nil, nil, autherr.ErrBadParameter.Withf("invalid signer %q: %v", signer, err)
			} else if key, err := crypto.ParsePrivateKeyPEM(pem, passphrase); err != nil {
				return nil, nil, autherr.ErrBadParameter.Withf("invalid signer %q: %v", signer, err)
			} else {
				opts = append(opts, auth.WithSigner(kid, key))
				pk = key
			}
		}
	}

	// Return success
	return opts, pk, nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func keyPEM(index int, signer *url.URL) (string, []byte, string, error) {
	if signer.Scheme != "" && signer.Scheme != "file" {
		return "", nil, "", fmt.Errorf("unsupported signer URL scheme: %q", signer.Scheme)
	}

	// Default kid
	kid := signer.Query().Get("kid")
	if kid == "" {
		kid = fmt.Sprintf("%s-%d", signerKid, index+1)
	}
	passphrase := signer.Query().Get("passphrase")

	// Read the data
	data, err := os.ReadFile(signer.Path)
	if err != nil {
		return "", nil, "", err
	}

	// Return the kid, data, and passphrase (if any)
	return kid, data, passphrase, nil
}

func defaultKeyPEM(ctx server.Cmd) (string, error) {
	// Get private key from keychain
	signer := ctx.GetString(signerKey)
	if signer != "" {
		return signer, nil
	}

	// Generate a new private key and store it in the keychain
	if key, err := crypto.GeneratePrivateKey(); err != nil {
		return "", err
	} else if pem, err := crypto.PrivateKeyPEM(key); err != nil {
		return "", err
	} else if err := ctx.Set(signerKey, pem); err != nil {
		return "", err
	} else {
		return pem, nil
	}
}
