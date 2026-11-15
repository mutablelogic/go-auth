//go:build integration

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

package manager

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	// Packages
	ldap "github.com/go-ldap/ldap/v3"
	cert "github.com/mutablelogic/go-auth/cert/cert"
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	test "github.com/mutablelogic/go-pg/pkg/test"
	require "github.com/stretchr/testify/require"
	testcontainers "github.com/testcontainers/testcontainers-go"
)

// The integration tests run against each directory, in a container which
// starts when a test first needs it, and is shared by the package's tests,
// until they've all run. LDAPMANAGER_INTEGRATION_SERVER chooses some of
// them, separated by commas, such as "openldap,389ds".

///////////////////////////////////////////////////////////////////////////////
// TYPES

// integrationServer is a directory which the tests run against
type integrationServer struct {
	Name           string
	Image          string
	TLSPort        string
	BaseDN         string
	BindDN         string
	BindPassword   string
	UserDN         string
	GroupDN        string
	Env            map[string]string
	ConnectTimeout time.Duration

	// Options returns the container's options, such as its TLS files
	Options func() ([]test.Opt, error)

	// Bootstrap prepares the directory, once it accepts connections
	Bootstrap func(context.Context, integrationServer, *test.Container, *Manager) error
}

// integrationContainer is a server's container, which is started once
type integrationContainer struct {
	once      sync.Once
	container *test.Container
	url       string
	err       error
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const integrationServerEnv = "LDAPMANAGER_INTEGRATION_SERVER"

var integrationServers = []integrationServer{
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
		Options:        openldapTLSOpts,
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
		Bootstrap:      bootstrap389DS,
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
		ConnectTimeout: 90 * time.Second,
		Options:        smbldsTLSOpts,
	},
}

var (
	containersMu sync.Mutex
	containers   = map[string]*integrationContainer{}
)

///////////////////////////////////////////////////////////////////////////////
// MAIN

// TestMain runs the tests, then stops the containers they started
func TestMain(m *testing.M) {
	code := m.Run()
	ctx := context.Background()
	containersMu.Lock()
	for name, c := range containers {
		if c.container != nil {
			if err := c.container.Close(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "closing %s: %v\n", name, err)
			}
		}
	}
	containersMu.Unlock()
	os.Exit(code)
}

///////////////////////////////////////////////////////////////////////////////
// HARNESS

// forEachServer runs the test against each chosen directory, with a new
// manager, connected to its container, which is disconnected after it
func forEachServer(t *testing.T, fn func(*testing.T, context.Context, integrationServer, *Manager)) {
	t.Helper()
	if testing.Short() {
		t.Skip("integration test")
	}
	for _, server := range chosenServers(t) {
		t.Run(server.Name, func(t *testing.T) {
			ctx := context.Background()
			url := startServer(t, ctx, server)
			manager := newManager(t, ctx, server, url)
			fn(t, ctx, server, manager)
		})
	}
}

// chosenServers returns the servers which LDAPMANAGER_INTEGRATION_SERVER
// names, or all of them, when it's not set
func chosenServers(t *testing.T) []integrationServer {
	t.Helper()
	names := strings.TrimSpace(os.Getenv(integrationServerEnv))
	if names == "" {
		return integrationServers
	}
	result := []integrationServer{}
	for _, name := range strings.Split(names, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		found := false
		for _, server := range integrationServers {
			if server.Name == name {
				result = append(result, server)
				found = true
			}
		}
		if !found {
			t.Fatalf("%s: unknown LDAP integration server %q", integrationServerEnv, name)
		}
	}
	return result
}

// startServer starts the server's container, once, and returns its ldaps
// URL, or fails the test when it can't be started
func startServer(t *testing.T, ctx context.Context, server integrationServer) string {
	t.Helper()
	containersMu.Lock()
	c, exists := containers[server.Name]
	if !exists {
		c = new(integrationContainer)
		containers[server.Name] = c
	}
	containersMu.Unlock()

	c.once.Do(func() {
		c.container, c.url, c.err = startContainer(ctx, server)
	})
	require.NoError(t, c.err, "starting %s", server.Name)
	return c.url
}

// startContainer starts the container, waits until the directory accepts a
// bind, and prepares it
func startContainer(ctx context.Context, server integrationServer) (*test.Container, string, error) {
	opts := []test.Opt{test.OptPorts(server.TLSPort)}
	if server.Options != nil {
		more, err := server.Options()
		if err != nil {
			return nil, "", err
		}
		opts = append(opts, more...)
	}
	for key, value := range server.Env {
		opts = append(opts, test.OptEnv(key, value))
	}

	container, err := test.NewContainer(ctx, "ldapmanager_"+server.Name, server.Image, opts...)
	if err != nil {
		return nil, "", err
	}
	port, err := container.GetPort(server.TLSPort)
	if err != nil {
		return container, "", err
	}
	url := fmt.Sprintf("%s://127.0.0.1:%s", schema.MethodSecure, port)

	// The port listens before the directory binds, so it's retried
	manager, err := managerOf(server, url)
	if err != nil {
		return container, "", err
	}
	defer manager.Disconnect(ctx)
	if err := connectWithin(ctx, manager, server.ConnectTimeout); err != nil {
		return container, "", err
	}
	if server.Bootstrap != nil {
		if err := server.Bootstrap(ctx, server, container, manager); err != nil {
			return container, "", err
		}
	}
	return container, url, nil
}

// newManager returns a manager connected to the server, which is
// disconnected when the test ends
func newManager(t *testing.T, ctx context.Context, server integrationServer, url string) *Manager {
	t.Helper()
	manager, err := managerOf(server, url)
	require.NoError(t, err)
	t.Cleanup(func() { _ = manager.Disconnect(ctx) })
	require.NoError(t, connectWithin(ctx, manager, server.ConnectTimeout))
	return manager
}

// managerOf returns a manager of the server, at the URL
func managerOf(server integrationServer, url string) (*Manager, error) {
	return New(
		WithUrl(url),
		WithBaseDN(server.BaseDN),
		WithUser(server.BindDN),
		WithPassword(server.BindPassword),
		WithUserDN(server.UserDN),
		WithGroupDN(server.GroupDN),
		WithSkipVerify(),
	)
}

// connectWithin connects, retrying until the timeout
func connectWithin(ctx context.Context, manager *Manager, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		err := manager.Connect(ctx)
		if err == nil || time.Now().After(deadline) {
			return err
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// searchBase reads the entry at the DN, which is how the tests check the
// directory has it
func searchBase(manager *Manager, dn string) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.conn == nil {
		return fmt.Errorf("not connected")
	}
	_, err := manager.conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)", []string{"dn"}, nil))
	return err
}

///////////////////////////////////////////////////////////////////////////////
// SERVERS

// bootstrap389DS creates the suffix, which 389 DS doesn't, and waits until
// it can be read
func bootstrap389DS(ctx context.Context, server integrationServer, container *test.Container, manager *Manager) error {
	exitCode, reader, err := container.Exec(ctx, []string{
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
		err := searchBase(manager, server.BaseDN)
		if err == nil || time.Now().After(deadline) {
			return err
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// openldapTLSOpts are OpenLDAP's certificate files
func openldapTLSOpts() ([]test.Opt, error) {
	caPEM, certPEM, keyPEM, err := tlsMaterials()
	if err != nil {
		return nil, err
	}
	return []test.Opt{test.OptFiles(
		testcontainers.ContainerFile{Reader: strings.NewReader(caPEM), ContainerFilePath: "/container/service/slapd/assets/certs/ca.crt", FileMode: 0o644},
		testcontainers.ContainerFile{Reader: strings.NewReader(certPEM), ContainerFilePath: "/container/service/slapd/assets/certs/ldap.crt", FileMode: 0o644},
		testcontainers.ContainerFile{Reader: strings.NewReader(keyPEM), ContainerFilePath: "/container/service/slapd/assets/certs/ldap.key", FileMode: 0o600},
	)}, nil
}

// smbldsTLSOpts are a script which writes SMB LDS's certificate files,
// when it starts
func smbldsTLSOpts() ([]test.Opt, error) {
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
	return []test.Opt{test.OptFile(testcontainers.ContainerFile{
		Reader:            strings.NewReader(script),
		ContainerFilePath: "/entrypoint.d/10-tls.sh",
		FileMode:          0o755,
	})}, nil
}

// tlsMaterials returns a CA, and a certificate for localhost which it
// signs, with its key, as PEM
func tlsMaterials() (string, string, string, error) {
	ca, err := cert.New(cert.WithCommonName("ldap integration test ca"), cert.WithEllipticKey("P256"), cert.WithExpiry(24*time.Hour), cert.WithCA())
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
