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
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	// Packages
	schema "github.com/djthorpe/go-auth/schema/ldap"
	ldap "github.com/go-ldap/ldap/v3"
	test "github.com/mutablelogic/go-pg/pkg/test"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

const (
	ldapIntegrationPort      = "389/tcp"
	ldapIntegration389DSPort = "3389/tcp"
)

type ldapIntegrationServer struct {
	Name           string
	Image          string
	Port           string
	BaseDN         string
	BindDN         string
	BindPassword   string
	UserDN         string
	GroupDN        string
	UserContainer  string
	GroupContainer string
	Env            map[string]string
	Options        []test.Opt
	ConnectTimeout time.Duration
	Bootstrap      func(context.Context, *testing.T, ldapIntegrationServer, *test.Container, *Manager) error
}

var ldapIntegrationServers = []ldapIntegrationServer{
	{
		Name:           "openldap",
		Image:          "osixia/openldap:1.5.0",
		Port:           ldapIntegrationPort,
		BaseDN:         "dc=example,dc=org",
		BindDN:         "cn=admin,dc=example,dc=org",
		BindPassword:   "admin",
		UserDN:         "ou=users",
		GroupDN:        "ou=groups",
		UserContainer:  "users",
		GroupContainer: "groups",
		Env: map[string]string{
			"LDAP_ORGANISATION":   "Example Org",
			"LDAP_DOMAIN":         "example.org",
			"LDAP_ADMIN_PASSWORD": "admin",
		},
		ConnectTimeout: 30 * time.Second,
	},
	{
		Name:           "389ds",
		Image:          "389ds/dirsrv:3.1",
		Port:           ldapIntegration389DSPort,
		BaseDN:         "dc=example,dc=org",
		BindDN:         "cn=Directory Manager",
		BindPassword:   "admin",
		UserDN:         "ou=users",
		GroupDN:        "ou=groups",
		UserContainer:  "users",
		GroupContainer: "groups",
		Env: map[string]string{
			"DS_DM_PASSWORD":     "admin",
			"DS_SUFFIX_NAME":     "dc=example,dc=org",
			"DS_STARTUP_TIMEOUT": "60",
		},
		ConnectTimeout: 60 * time.Second,
		Bootstrap:      bootstrap389DS,
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
	selected := strings.TrimSpace(os.Getenv("LDAPMANAGER_INTEGRATION_SERVER"))
	if selected == "" {
		return ldapIntegrationServers
	}

	allowed := make(map[string]ldapIntegrationServer, len(ldapIntegrationServers))
	for _, server := range ldapIntegrationServers {
		allowed[server.Name] = server
	}

	result := make([]ldapIntegrationServer, 0, len(ldapIntegrationServers))
	for _, name := range strings.Split(selected, ",") {
		name = strings.TrimSpace(name)
		server, ok := allowed[name]
		if !ok {
			t.Fatalf("unknown LDAP integration server %q", name)
		}
		result = append(result, server)
	}

	return result
}

func newIntegrationManager(t *testing.T, ctx context.Context, server ldapIntegrationServer) *Manager {
	t.Helper()

	opt := make([]test.Opt, 0, len(server.Env)+len(server.Options)+1)
	portName := strings.TrimSpace(server.Port)
	if portName == "" {
		portName = ldapIntegrationPort
	}
	opt = append(opt, test.OptPorts(portName))
	for key, value := range server.Env {
		opt = append(opt, test.OptEnv(key, value))
	}
	opt = append(opt, server.Options...)

	container, err := test.NewContainer(ctx, "ldapmanager_"+server.Name, server.Image, opt...)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, container.Close(ctx))
	})

	port, err := container.GetPort(portName)
	require.NoError(t, err)

	manager, err := New(
		WithUrl(fmt.Sprintf("ldap://127.0.0.1:%s", port)),
		WithBaseDN(server.BaseDN),
		WithUser(server.BindDN),
		WithPassword(server.BindPassword),
		WithUserDN(server.UserDN),
		WithGroupDN(server.GroupDN),
	)
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

	_, err = manager.Create(ctx, server.UserDN, url.Values{
		"objectClass": {"top", "organizationalUnit"},
		"ou":          {server.UserContainer},
	})
	require.NoError(t, err)

	_, err = manager.Create(ctx, server.GroupDN, url.Values{
		"objectClass": {"top", "organizationalUnit"},
		"ou":          {server.GroupContainer},
	})
	require.NoError(t, err)

	return manager
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
