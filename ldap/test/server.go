// Copyright 2026 David Thorpe
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	// Packages
	ldap "github.com/go-ldap/ldap/v3"
	cert "github.com/mutablelogic/go-auth/cert/cert"
	pgtest "github.com/mutablelogic/go-pg/pkg/test"
	testcontainers "github.com/testcontainers/testcontainers-go"
)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

var servers = []Server{
	{
		Name:         "openldap",
		Image:        "osixia/openldap:1.5.0",
		TLSPort:      "636/tcp",
		BaseDN:       "dc=example,dc=org",
		BindDN:       "cn=admin,dc=example,dc=org",
		BindPassword: "admin",
		UserDN:       "ou=users",
		GroupDN:      "ou=groups",
		Env: map[string]string{
			"LDAP_ORGANISATION":      "Example Org",
			"LDAP_DOMAIN":            "example.org",
			"LDAP_ADMIN_PASSWORD":    "admin",
			"LDAP_TLS_VERIFY_CLIENT": "never",
		},
		ConnectTimeout: 30 * time.Second,
		options:        openldapTLSOpts,
	},
	{
		Name:         "389ds",
		Image:        "389ds/dirsrv:latest",
		TLSPort:      "3636/tcp",
		BaseDN:       "dc=example,dc=org",
		BindDN:       "cn=Directory Manager",
		BindPassword: "admin",
		UserDN:       "ou=users",
		GroupDN:      "ou=groups",
		Env: map[string]string{
			"DS_DM_PASSWORD":     "admin",
			"DS_SUFFIX_NAME":     "dc=example,dc=org",
			"DS_STARTUP_TIMEOUT": "60",
		},
		ConnectTimeout: 60 * time.Second,
		bootstrap:      bootstrap389DS,
	},
	{
		Name:         "smblds",
		Image:        "smblds/smblds:latest",
		TLSPort:      "636/tcp",
		BaseDN:       "dc=example,dc=org",
		BindDN:       "CN=Administrator,CN=Users,DC=example,DC=org",
		BindPassword: "Passw0rd!",
		UserDN:       "ou=users",
		GroupDN:      "ou=groups",
		Env: map[string]string{
			"REALM":                     "EXAMPLE.ORG",
			"DOMAIN":                    "EXAMPLE",
			"ADMINPASS":                 "Passw0rd!",
			"INSECURE_LDAP":             "true",
			"INSECURE_PASSWORDSETTINGS": "true",
		},
		ActiveDirectory: true,
		ConnectTimeout:  90 * time.Second,
		options:         smbldsTLSOpts,
	},
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// bootstrap389DS creates the suffix, which 389 DS doesn't, and waits until
// it can be read
func bootstrap389DS(ctx context.Context, server Server, c *pgtest.Container, conn *ldap.Conn) error {
	exitCode, reader, err := c.Exec(ctx, []string{
		"dsconf", "localhost", "backend", "create",
		"--be-name", "userRoot",
		"--suffix", server.BaseDN,
		"--create-suffix",
	})
	if err != nil {
		return err
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	if exitCode != 0 {
		return fmt.Errorf("389ds bootstrap failed with exit code %d: %s", exitCode, strings.TrimSpace(string(output)))
	}

	deadline := time.Now().Add(15 * time.Second)
	for {
		_, err := conn.Search(ldap.NewSearchRequest(server.BaseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)", []string{"dn"}, nil))
		if err == nil || time.Now().After(deadline) {
			return err
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// openldapTLSOpts are OpenLDAP's certificate files
func openldapTLSOpts() ([]pgtest.Opt, error) {
	caPEM, certPEM, keyPEM, err := tlsMaterials()
	if err != nil {
		return nil, err
	}
	return []pgtest.Opt{pgtest.OptFiles(
		testcontainers.ContainerFile{Reader: strings.NewReader(caPEM), ContainerFilePath: "/container/service/slapd/assets/certs/ca.crt", FileMode: 0o644},
		testcontainers.ContainerFile{Reader: strings.NewReader(certPEM), ContainerFilePath: "/container/service/slapd/assets/certs/ldap.crt", FileMode: 0o644},
		testcontainers.ContainerFile{Reader: strings.NewReader(keyPEM), ContainerFilePath: "/container/service/slapd/assets/certs/ldap.key", FileMode: 0o600},
	)}, nil
}

// smbldsTLSOpts are a script which writes SMB LDS's certificate files,
// when it starts
func smbldsTLSOpts() ([]pgtest.Opt, error) {
	caPEM, certPEM, keyPEM, err := tlsMaterials()
	if err != nil {
		return nil, err
	}
	script := fmt.Sprintf(`#!/bin/sh
set -eu
install -d -m 0700 /var/lib/samba/private/tls
cat > /var/lib/samba/private/tls/ca.pem <<'EOF_CA'
%sEOF_CA
cat > /var/lib/samba/private/tls/cert.pem <<'EOF_CERT'
%sEOF_CERT
cat > /var/lib/samba/private/tls/key.pem <<'EOF_KEY'
%sEOF_KEY
chmod 0644 /var/lib/samba/private/tls/ca.pem /var/lib/samba/private/tls/cert.pem
chmod 0600 /var/lib/samba/private/tls/key.pem
`, caPEM, certPEM, keyPEM)
	return []pgtest.Opt{pgtest.OptFile(testcontainers.ContainerFile{
		Reader:            strings.NewReader(script),
		ContainerFilePath: "/entrypoint.d/10-tls.sh",
		FileMode:          0o755,
	})}, nil
}

// tlsMaterials returns a CA, and a certificate for localhost which it
// signs, with its key, as PEM
func tlsMaterials() (string, string, string, error) {
	ca, err := cert.New(cert.WithCommonName("ldap test ca"), cert.WithEllipticKey("P256"), cert.WithExpiry(24*time.Hour), cert.WithCA())
	if err != nil {
		return "", "", "", err
	}
	leaf, err := cert.New(cert.WithCommonName("localhost"), cert.WithEllipticKey("P256"), cert.WithExpiry(24*time.Hour), cert.WithSAN("localhost", "127.0.0.1"), cert.WithSigner(ca))
	if err != nil {
		return "", "", "", err
	}
	var caPEM, certPEM, keyPEM bytes.Buffer
	if err := ca.Write(&caPEM); err != nil {
		return "", "", "", err
	}
	if err := leaf.Write(&certPEM); err != nil {
		return "", "", "", err
	}
	if err := leaf.WritePrivateKey(&keyPEM); err != nil {
		return "", "", "", err
	}
	return caPEM.String(), certPEM.String(), keyPEM.String(), nil
}
