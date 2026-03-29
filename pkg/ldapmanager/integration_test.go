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

package ldap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	// Packages
	cert "github.com/djthorpe/go-auth/pkg/cert"
	schema "github.com/djthorpe/go-auth/schema/ldap"
	ldap "github.com/go-ldap/ldap/v3"
	test "github.com/mutablelogic/go-pg/pkg/test"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
	testcontainers "github.com/testcontainers/testcontainers-go"
)

const (
	ldapIntegrationTLSPort      = "636/tcp"
	ldapIntegration389DSTLSPort = "3636/tcp"
)

type ldapIntegrationServer struct {
	Name                         string
	PasswordCompat               bool
	PasswordChangeInvalidatesOld bool
	Image                        string
	TLSPort                      string
	BaseDN                       string
	BindDN                       string
	BindPassword                 string
	UserDN                       string
	GroupDN                      string
	UserContainer                string
	GroupContainer               string
	Env                          map[string]string
	Options                      []test.Opt
	ConnectTimeout               time.Duration
	Bootstrap                    func(context.Context, *testing.T, ldapIntegrationServer, *test.Container, *Manager) error
}

var ldapIntegrationServers = []ldapIntegrationServer{
	{
		Name:                         "openldap",
		PasswordCompat:               true,
		PasswordChangeInvalidatesOld: true,
		Image:                        "osixia/openldap:1.5.0",
		TLSPort:                      ldapIntegrationTLSPort,
		BaseDN:                       "dc=example,dc=org",
		BindDN:                       "cn=admin,dc=example,dc=org",
		BindPassword:                 "admin",
		UserDN:                       "ou=users",
		GroupDN:                      "ou=groups",
		UserContainer:                "users",
		GroupContainer:               "groups",
		Env: map[string]string{
			"LDAP_ORGANISATION":      "Example Org",
			"LDAP_DOMAIN":            "example.org",
			"LDAP_ADMIN_PASSWORD":    "admin",
			"LDAP_TLS_VERIFY_CLIENT": "never",
		},
		ConnectTimeout: 30 * time.Second,
	},
	{
		Name:                         "389ds",
		PasswordCompat:               true,
		PasswordChangeInvalidatesOld: true,
		Image:                        "389ds/dirsrv:latest",
		TLSPort:                      ldapIntegration389DSTLSPort,
		BaseDN:                       "dc=example,dc=org",
		BindDN:                       "cn=Directory Manager",
		BindPassword:                 "admin",
		UserDN:                       "ou=users",
		GroupDN:                      "ou=groups",
		UserContainer:                "users",
		GroupContainer:               "groups",
		Env: map[string]string{
			"DS_DM_PASSWORD":     "admin",
			"DS_SUFFIX_NAME":     "dc=example,dc=org",
			"DS_STARTUP_TIMEOUT": "60",
		},
		ConnectTimeout: 60 * time.Second,
		Bootstrap:      bootstrap389DS,
	},
	{
		Name:                         "smblds",
		PasswordCompat:               true,
		PasswordChangeInvalidatesOld: false,
		Image:                        "smblds/smblds:latest",
		TLSPort:                      ldapIntegrationTLSPort,
		BaseDN:                       "dc=example,dc=org",
		BindDN:                       "CN=Administrator,CN=Users,DC=example,DC=org",
		BindPassword:                 "Passw0rd!",
		UserDN:                       "ou=users",
		GroupDN:                      "ou=groups",
		UserContainer:                "users",
		GroupContainer:               "groups",
		Env: map[string]string{
			"REALM":                     "EXAMPLE.ORG",
			"DOMAIN":                    "EXAMPLE",
			"ADMINPASS":                 "Passw0rd!",
			"INSECURE_LDAP":             "true",
			"INSECURE_PASSWORDSETTINGS": "true",
		},
		ConnectTimeout: 90 * time.Second,
	},
}

func forEachLDAPIntegrationServer(t *testing.T, fn func(*testing.T, context.Context, ldapIntegrationServer, *Manager)) {
	t.Helper()

	if testing.Short() {
		t.Skip("integration test")
	}

	for _, server := range selectedLDAPIntegrationServers(t) {
		server := server
		t.Run(server.Name, func(t *testing.T) {
			ctx := context.Background()
			manager := newIntegrationManager(t, ctx, server)
			fn(t, ctx, server, manager)
		})
	}
}

func selectedLDAPIntegrationServers(t *testing.T) []ldapIntegrationServer {
	t.Helper()
	selectedNames := selectedLDAPIntegrationServerNames()
	if len(selectedNames) == 0 {
		return ldapIntegrationServers
	}

	result := make([]ldapIntegrationServer, 0, len(ldapIntegrationServers))
	for _, server := range ldapIntegrationServers {
		if _, ok := selectedNames[server.Name]; ok {
			result = append(result, server)
		}
	}

	requireKnownLDAPIntegrationServers(t, result, selectedNames)

	return result
}

func selectedLDAPIntegrationServerNames() map[string]struct{} {
	selected := strings.TrimSpace(os.Getenv("LDAPMANAGER_INTEGRATION_SERVER"))
	if selected == "" {
		return nil
	}

	result := make(map[string]struct{}, len(ldapIntegrationServers))
	for _, name := range strings.Split(selected, ",") {
		if name = strings.TrimSpace(name); name != "" {
			result[name] = struct{}{}
		}
	}

	return result
}

func requireKnownLDAPIntegrationServers(t *testing.T, selected []ldapIntegrationServer, requested map[string]struct{}) {
	t.Helper()

	if len(selected) == len(requested) {
		return
	}

	for name := range requested {
		if !containsLDAPIntegrationServer(selected, name) {
			t.Fatalf("unknown LDAP integration server %q", name)
		}
	}
}

func containsLDAPIntegrationServer(servers []ldapIntegrationServer, name string) bool {
	for _, server := range servers {
		if server.Name == name {
			return true
		}
	}

	return false
}

func newIntegrationManager(t *testing.T, ctx context.Context, server ldapIntegrationServer) *Manager {
	t.Helper()

	opt := make([]test.Opt, 0, len(server.Env)+len(server.Options)+2)
	tlsPortName := strings.TrimSpace(server.TLSPort)
	if tlsPortName == "" {
		tlsPortName = ldapIntegrationTLSPort
	}
	portNames := []string{tlsPortName}
	opt = append(opt, test.OptPorts(portNames...))
	if server.Name == "openldap" {
		opt = append(opt, openldapTLSBootstrapOpt(t))
	}
	if server.Name == "smblds" {
		opt = append(opt, smbldsTLSBootstrapOpt(t))
	}
	for key, value := range server.Env {
		opt = append(opt, test.OptEnv(key, value))
	}
	opt = append(opt, server.Options...)

	container, err := test.NewContainer(ctx, "ldapmanager_"+server.Name, server.Image, opt...)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, container.Close(ctx))
	})

	port, err := container.GetPort(tlsPortName)
	require.NoError(t, err)

	managerOpt := []Opt{
		WithUrl(fmt.Sprintf("%s://127.0.0.1:%s", schema.MethodSecure, port)),
		WithBaseDN(server.BaseDN),
		WithUser(server.BindDN),
		WithPassword(server.BindPassword),
		WithUserDN(server.UserDN),
		WithGroupDN(server.GroupDN),
		WithSkipVerify(),
	}
	manager, err := New(managerOpt...)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, manager.Disconnect())
	})

	connectTimeout := server.ConnectTimeout
	if connectTimeout <= 0 {
		connectTimeout = 30 * time.Second
	}
	deadline := time.Now().Add(connectTimeout)
	for {
		err = manager.Connect()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			require.NoError(t, err)
		}
		time.Sleep(250 * time.Millisecond)
	}

	if server.Bootstrap != nil {
		require.NoError(t, server.Bootstrap(ctx, t, server, container, manager))
	}

	manager.discoveryOnce.Do(func() {
		manager.discoverSchemas(ctx, nil)
	})

	setupDeadline := time.Now().Add(connectTimeout)
	for {
		err = ensureIntegrationContainers(ctx, manager, server)
		if err == nil {
			break
		}
		if !isRetryableIntegrationSetupError(err) || time.Now().After(setupDeadline) {
			require.NoError(t, err)
		}
		_ = manager.Disconnect()
		for {
			err = manager.Connect()
			if err == nil {
				break
			}
			if time.Now().After(setupDeadline) {
				require.NoError(t, err)
			}
			time.Sleep(250 * time.Millisecond)
		}
		time.Sleep(250 * time.Millisecond)
	}

	return manager
}

func ensureIntegrationContainers(ctx context.Context, manager *Manager, server ldapIntegrationServer) error {
	if err := ensureIntegrationContainer(ctx, manager, server.UserDN, server.UserContainer); err != nil {
		return err
	}
	return ensureIntegrationContainer(ctx, manager, server.GroupDN, server.GroupContainer)
}

func ensureIntegrationContainer(ctx context.Context, manager *Manager, dn, container string) error {
	_, err := manager.Create(ctx, dn, url.Values{
		"objectClass": {"top", "organizationalUnit"},
		"ou":          {container},
	})
	if err == nil || errors.Is(err, httpresponse.ErrConflict) {
		return nil
	}
	return err
}

func isRetryableIntegrationSetupError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection closed") || strings.Contains(msg, "not connected")
}

func smbldsTLSBootstrapOpt(t *testing.T) test.Opt {
	t.Helper()

	caPEM, certPEM, keyPEM := generateIntegrationTLSMaterials(t)
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

	return test.OptFile(testcontainers.ContainerFile{
		Reader:            strings.NewReader(script),
		ContainerFilePath: "/entrypoint.d/10-tls.sh",
		FileMode:          0o755,
	})
}

func openldapTLSBootstrapOpt(t *testing.T) test.Opt {
	t.Helper()

	caPEM, certPEM, keyPEM := generateIntegrationTLSMaterials(t)
	files := []testcontainers.ContainerFile{
		{
			Reader:            strings.NewReader(caPEM),
			ContainerFilePath: "/container/service/slapd/assets/certs/ca.crt",
			FileMode:          0o644,
		},
		{
			Reader:            strings.NewReader(certPEM),
			ContainerFilePath: "/container/service/slapd/assets/certs/ldap.crt",
			FileMode:          0o644,
		},
		{
			Reader:            strings.NewReader(keyPEM),
			ContainerFilePath: "/container/service/slapd/assets/certs/ldap.key",
			FileMode:          0o600,
		},
	}
	return test.OptFiles(files...)
}

func generateIntegrationTLSMaterials(t *testing.T) (string, string, string) {
	t.Helper()

	ca, err := cert.New(
		cert.WithCommonName("ldap integration test ca"),
		cert.WithEllipticKey("P256"),
		cert.WithExpiry(24*time.Hour),
		cert.WithCA(),
	)
	require.NoError(t, err)

	leaf, err := cert.New(
		cert.WithCommonName("localhost"),
		cert.WithEllipticKey("P256"),
		cert.WithExpiry(24*time.Hour),
		cert.WithSAN("localhost", "127.0.0.1"),
		cert.WithSigner(ca),
	)
	require.NoError(t, err)

	var caPEM bytes.Buffer
	require.NoError(t, ca.Write(&caPEM))

	var certPEM bytes.Buffer
	require.NoError(t, leaf.Write(&certPEM))

	var keyPEM bytes.Buffer
	require.NoError(t, leaf.WritePrivateKey(&keyPEM))

	return caPEM.String(), certPEM.String(), keyPEM.String()
}

func bootstrap389DS(ctx context.Context, t *testing.T, server ldapIntegrationServer, container *test.Container, manager *Manager) error {
	t.Helper()

	command := []string{
		"dsconf",
		"localhost",
		"backend",
		"create",
		"--be-name", "userRoot",
		"--suffix", server.BaseDN,
		"--create-suffix",
	}

	exitCode, reader, err := container.Exec(ctx, command)
	if err != nil {
		return err
	}
	output, readErr := io.ReadAll(reader)
	if readErr != nil {
		return readErr
	}
	if exitCode != 0 {
		return fmt.Errorf("389ds bootstrap failed with exit code %d: %s", exitCode, strings.TrimSpace(string(output)))
	}

	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := manager.get(ctx, ldap.ScopeBaseObject, server.BaseDN, "(objectClass=*)"); err == nil {
			return nil
		} else if time.Now().After(deadline) {
			return err
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func assertMembershipPresent(t *testing.T, group, user *schema.Object, expectSingle bool) {
	t.Helper()
	require.NotNil(t, group)
	require.NotNil(t, user)

	for _, attr := range groupMembershipAttrs(group.GetAll("objectClass")) {
		values := group.GetAll(attr)
		expected := groupMembershipValues(attr, []*schema.Object{user})
		for _, value := range expected {
			assert.Contains(t, values, value)
			if !expectSingle {
				assert.Equal(t, 1, countString(values, value))
			}
		}
	}
}

func assertMembershipAbsent(t *testing.T, group, user *schema.Object) {
	t.Helper()
	require.NotNil(t, group)
	require.NotNil(t, user)

	for _, attr := range groupMembershipAttrs(group.GetAll("objectClass")) {
		values := group.GetAll(attr)
		for _, value := range groupMembershipValues(attr, []*schema.Object{user}) {
			assert.NotContains(t, values, value)
		}
	}
}

func countString(values []string, target string) int {
	count := 0
	for _, value := range values {
		if value == target {
			count++
		}
	}
	return count
}

func newIntegrationUserAttrs(manager *Manager, username, fullName, password string) url.Values {
	attrs := url.Values{}
	fullName = strings.TrimSpace(fullName)
	if fullName == "" {
		fullName = username
	}
	attrs.Set("cn", fullName)
	attrs.Set("sn", integrationSurname(fullName))
	if strings.TrimSpace(password) != "" {
		attrs.Set("userPassword", password)
	}
	if containsFold(manager.users.ObjectClass, "posixAccount") {
		attrs.Set("homeDirectory", "/home/"+username)
	}
	return attrs
}

func integrationUserRelativeDN(manager *Manager, username string) string {
	return userNamingAttribute(manager.users.ObjectClass) + "=" + ldap.EscapeDN(username) + "," + manager.users.DN.String()
}

func integrationSurname(fullName string) string {
	fields := strings.Fields(fullName)
	if len(fields) == 0 {
		return "User"
	}
	return fields[len(fields)-1]
}
