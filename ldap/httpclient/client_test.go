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

package httpclient_test

import (
	"context"
	"strings"
	"testing"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	httpclient "github.com/mutablelogic/go-auth/ldap/httpclient"
	httphandler "github.com/mutablelogic/go-auth/ldap/httphandler"
	manager "github.com/mutablelogic/go-auth/ldap/manager"
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	ldaptest "github.com/mutablelogic/go-auth/ldap/test"
	types "github.com/mutablelogic/go-server/pkg/types"
	test "github.com/mutablelogic/go-server/test"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	ldaptest.Main(m)
}

// newClient returns a client of a test server, which serves the handlers
// with a manager whose users and groups are in organizational units of the
// test's, and checks every request and response against the OpenAPI
// specification
func newClient(t *testing.T, ctx context.Context, server ldaptest.Server, m *manager.Manager) *httpclient.Client {
	t.Helper()
	mgr := ldaptest.Manager(t, ctx, server, manager.WithUserDN(ldaptest.OU(t, ctx, m)), manager.WithGroupDN(ldaptest.OU(t, ctx, m)))
	s := test.NewServer(t, httphandler.RegisterHandlers(mgr, false))
	c, err := httpclient.New(s.URL + test.Prefix)
	require.NoError(t, err)
	return c
}

// userAttrs returns a user's attributes, with the password
func userAttrs(name, password string) schema.Attrs {
	return schema.Attrs{
		"cn":            {name + " Example"},
		"sn":            {"Example"},
		"userPassword":  {password},
		"homeDirectory": {"/home/" + name},
	}
}

func Test_Client(t *testing.T) {
	ldaptest.ForEach(t, func(t *testing.T, ctx context.Context, server ldaptest.Server, m *manager.Manager) {
		c := newClient(t, ctx, server, m)

		t.Run("Schema", func(t *testing.T) {
			classes, err := c.ListObjectClasses(ctx, schema.ObjectClassListRequest{Filter: types.Ptr("person")})
			require.NoError(t, err)
			require.NotEmpty(t, classes.Body)
			assert.Equal(t, "person", classes.Body[0].Identifier())
			attrs, err := c.ListAttributeTypes(ctx, schema.AttributeTypeListRequest{OffsetLimit: schema.OffsetLimit{Limit: types.Ptr(uint64(3))}})
			require.NoError(t, err)
			assert.Len(t, attrs.Body, 3)
		})

		t.Run("Users", func(t *testing.T) {
			user, err := c.CreateUser(ctx, "alice", userAttrs("alice", "first Passw0rd!"), true)
			require.NoError(t, err)
			assert.Equal(t, user.Get("uidNumber"), user.Get("gidNumber"))
			_, err = c.CreateUser(ctx, "alice", userAttrs("alice", "first Passw0rd!"), true)
			assert.ErrorIs(t, err, auth.ErrConflict)

			got, err := c.GetUser(ctx, "alice")
			require.NoError(t, err)
			assert.Equal(t, user.DN, got.DN)
			list, err := c.ListUsers(ctx, schema.UserListRequest{})
			require.NoError(t, err)
			assert.Equal(t, uint64(1), list.Count)
			updated, err := c.UpdateUser(ctx, "alice", schema.Attrs{"description": {"Updated"}})
			require.NoError(t, err)
			assert.Equal(t, types.Ptr("Updated"), updated.Get("description"))
			_, err = c.GetUser(ctx, "missing")
			assert.ErrorIs(t, err, auth.ErrNotFound)
		})

		t.Run("Groups", func(t *testing.T) {
			group, err := c.CreateGroup(ctx, "eng", nil)
			require.NoError(t, err)
			assert.Equal(t, types.Ptr("eng"), group.Get("cn"))

			_, err = c.AddGroupUsers(ctx, "eng", "alice")
			require.NoError(t, err)
			members, err := c.ListUsers(ctx, schema.UserListRequest{Group: types.Ptr("eng")})
			require.NoError(t, err)
			assert.Equal(t, uint64(1), members.Count)
			groups, err := c.ListGroups(ctx, schema.GroupListRequest{User: types.Ptr("alice")})
			require.NoError(t, err)
			assert.Equal(t, uint64(1), groups.Count)
			_, err = c.RemoveGroupUsers(ctx, "eng", "alice")
			require.NoError(t, err)
			_, err = c.AddGroupUsers(ctx, "eng")
			assert.ErrorIs(t, err, auth.ErrBadParameter, "no users")

			_, err = c.UpdateGroup(ctx, "eng", schema.Attrs{"cn": {"engineering"}})
			require.NoError(t, err)
			_, err = c.GetGroup(ctx, "engineering")
			require.NoError(t, err)
			_, err = c.DeleteGroup(ctx, "engineering")
			require.NoError(t, err)
			_, err = c.GetGroup(ctx, "engineering")
			assert.ErrorIs(t, err, auth.ErrNotFound)
		})

		t.Run("Objects", func(t *testing.T) {
			ou := ldaptest.OU(t, ctx, m)
			dn := "ou=a/b," + ou
			object, err := c.CreateObject(ctx, dn, schema.Attrs{"objectClass": {"top", "organizationalUnit"}, "ou": {"a/b"}})
			require.NoError(t, err, "a DN with a slash")
			assert.True(t, strings.EqualFold(dn, object.DN))
			got, err := c.GetObject(ctx, dn)
			require.NoError(t, err)
			assert.Equal(t, object.DN, got.DN)
			list, err := c.ListObjects(ctx, schema.ObjectListRequest{Prefix: types.Ptr(ou)})
			require.NoError(t, err)
			assert.Equal(t, uint64(2), list.Count)
			_, err = c.UpdateObject(ctx, dn, schema.Attrs{"description": {"Slashed"}})
			require.NoError(t, err)
			_, err = c.DeleteObject(ctx, dn)
			require.NoError(t, err)
			_, err = c.GetObject(ctx, dn)
			assert.ErrorIs(t, err, auth.ErrNotFound)
		})

		t.Run("Passwords", func(t *testing.T) {
			user, err := c.GetUser(ctx, "alice")
			require.NoError(t, err)
			bound, err := c.BindObject(ctx, user.DN, "first Passw0rd!")
			require.NoError(t, err)
			assert.Equal(t, user.DN, bound.DN)
			_, err = c.BindObject(ctx, user.DN, "wrong Passw0rd!")
			assert.ErrorIs(t, err, auth.ErrInvalidProvider)

			response, err := c.ChangeObjectPassword(ctx, user.DN, schema.ObjectPasswordRequest{Old: "first Passw0rd!"})
			require.NoError(t, err)
			require.NotEmpty(t, response.GeneratedPassword)
			_, err = c.BindObject(ctx, user.DN, response.GeneratedPassword)
			assert.NoError(t, err)

			_, err = c.DeleteUser(ctx, "alice")
			require.NoError(t, err)
		})
	})
}
