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

package manager_test

import (
	"context"
	"strings"
	"testing"
	"time"

	// Packages
	ldapv3 "github.com/go-ldap/ldap/v3"
	manager "github.com/mutablelogic/go-auth/ldap/manager"
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	test "github.com/mutablelogic/go-auth/ldap/test"
	types "github.com/mutablelogic/go-server/pkg/types"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_Status(t *testing.T) {
	test.ForEach(t, func(t *testing.T, ctx context.Context, server test.Server, m *manager.Manager) {
		status := m.Status()
		assert.True(t, status.Connected)
		assert.Equal(t, "127.0.0.1", status.Host)
		assert.NotZero(t, status.Port)
		assert.Equal(t, server.BindDN, status.User)
		assert.True(t, strings.EqualFold(server.BaseDN, status.BaseDN))
		assert.True(t, strings.EqualFold(server.UserDN+","+server.BaseDN, status.UserDN), status.UserDN)
		assert.True(t, strings.EqualFold(server.GroupDN+","+server.BaseDN, status.GroupDN), status.GroupDN)

		// It follows the connection
		require.NoError(t, m.Disconnect(ctx))
		assert.False(t, m.Status().Connected)
		require.NoError(t, m.Connect(ctx))
		assert.True(t, m.Status().Connected)
	})
}

func Test_StatusNotWaiting(t *testing.T) {
	// The status doesn't wait for a request, which holds the manager's lock
	d := test.NewFake(t, false)
	d.Stall = func(op uint8, _ string) bool { return op == ldapv3.ApplicationAddRequest }
	m, err := manager.New(manager.WithUrl(d.URL("ldap")), manager.WithBaseDN("dc=example,dc=test"))
	require.NoError(t, err)
	assert.False(t, m.Status().Connected, "not yet")
	assert.Empty(t, m.Status().UserDN, "no users")
	require.NoError(t, m.Connect(context.Background()))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		_, _ = m.Create(ctx, "ou=a", schema.Attrs{"objectClass": {"organizationalUnit"}, "ou": {"a"}})
	}()
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	assert.True(t, m.Status().Connected)
	assert.Less(t, time.Since(start), 500*time.Millisecond)
}

func Test_ObjectListChildren(t *testing.T) {
	test.ForEach(t, func(t *testing.T, ctx context.Context, server test.Server, m *manager.Manager) {
		ou := test.OU(t, ctx, m)
		for _, dn := range []string{"ou=a," + ou, "ou=b,ou=a," + ou, "ou=c," + ou} {
			name := strings.TrimPrefix(strings.SplitN(dn, ",", 2)[0], "ou=")
			_, err := m.Create(ctx, dn, unit(name))
			require.NoError(t, err)
		}

		// Only the children, not the entry, or its grandchildren
		list, err := m.List(ctx, schema.ObjectListRequest{Prefix: types.Ptr(ou), Children: true})
		require.NoError(t, err)
		var names []string
		for _, object := range list.Body {
			names = append(names, strings.ToLower(strings.SplitN(object.DN, ",", 2)[0]))
		}
		assert.ElementsMatch(t, []string{"ou=a", "ou=c"}, names)

		// Without a prefix, the base DN's, which has the OU
		list, err = m.List(ctx, schema.ObjectListRequest{Children: true, ListRequest: schema.ListRequest{Attr: []string{"1.1"}}})
		require.NoError(t, err)
		found := false
		for _, object := range list.Body {
			found = found || strings.EqualFold(object.DN, ou)
			assert.Len(t, strings.Split(object.DN, ","), len(strings.Split(server.BaseDN, ","))+1, object.DN)
		}
		assert.True(t, found, "the OU")
	})
}
