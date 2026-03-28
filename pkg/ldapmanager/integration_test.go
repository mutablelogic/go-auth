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
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	// Packages
	schema "github.com/djthorpe/go-auth/schema/ldap"
	test "github.com/mutablelogic/go-pg/pkg/test"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

const ldapIntegrationPort = "389/tcp"

type ldapIntegrationServer struct {
	Name           string
	Image          string
	BaseDN         string
	BindDN         string
	BindPassword   string
	UserDN         string
	GroupDN        string
	UserContainer  string
	GroupContainer string
	Env            map[string]string
}

var ldapIntegrationServers = []ldapIntegrationServer{
	{
		Name:           "openldap",
		Image:          "osixia/openldap:1.5.0",
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
	},
}

func TestLDAPIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	for _, server := range selectedLDAPIntegrationServers(t) {
		server := server
		t.Run(server.Name, func(t *testing.T) {
			ctx := context.Background()
			manager := newIntegrationManager(t, ctx, server)

			group, err := manager.CreateGroup(ctx, "eng", nil)
			require.NoError(t, err)
			require.NotNil(t, group)

			userAttrs := url.Values{
				"cn": {"Alice Example"},
				"sn": {"Example"},
			}
			allocateGID := false
			if containsFold(manager.users.ObjectClass, "posixAccount") {
				userAttrs.Set("homeDirectory", "/home/alice")
				allocateGID = true
			}

			user, err := manager.CreateUser(ctx, "alice", userAttrs, allocateGID)
			require.NoError(t, err)
			require.NotNil(t, user)

			group, err = manager.AddGroupUsers(ctx, "eng", "alice")
			require.NoError(t, err)

			assertMembershipPresent(t, group, user, true)

			group, err = manager.AddGroupUsers(ctx, "eng", "alice")
			require.NoError(t, err)
			assertMembershipPresent(t, group, user, false)

			group, err = manager.RemoveGroupUsers(ctx, "eng", "alice")
			require.NoError(t, err)
			assertMembershipAbsent(t, group, user)

			group, err = manager.RemoveGroupUsers(ctx, "eng", "alice")
			require.NoError(t, err)
			assertMembershipAbsent(t, group, user)
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

	opt := make([]test.Opt, 0, len(server.Env)+1)
	opt = append(opt, test.OptPorts(ldapIntegrationPort))
	for key, value := range server.Env {
		opt = append(opt, test.OptEnv(key, value))
	}

	container, err := test.NewContainer(ctx, "ldapmanager_"+server.Name, server.Image, opt...)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, container.Close(ctx))
	})

	port, err := container.GetPort(ldapIntegrationPort)
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

	deadline := time.Now().Add(30 * time.Second)
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
