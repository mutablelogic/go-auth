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
	"strconv"
	"testing"

	// Packages
	manager "github.com/mutablelogic/go-auth/ldap/manager"
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	test "github.com/mutablelogic/go-auth/ldap/test"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

// usersIn returns a manager whose users are in a new organizational unit
// of the test's
func usersIn(t *testing.T, ctx context.Context, server test.Server, m *manager.Manager) *manager.Manager {
	t.Helper()
	return test.Manager(t, ctx, server, manager.WithUserDN(test.OU(t, ctx, m)))
}

// userAttrs returns a user's attributes, with the password, and, for a
// posixAccount, a home directory
func userAttrs(name, password string) schema.Attrs {
	return schema.Attrs{
		"cn":            {name + " Example"},
		"sn":            {"Example"},
		"userPassword":  {password},
		"homeDirectory": {"/home/" + name},
	}
}

func Test_User(t *testing.T) {
	test.ForEach(t, func(t *testing.T, ctx context.Context, server test.Server, m *manager.Manager) {
		users := usersIn(t, ctx, server, m)

		// The directory's classes, which are Active Directory's user, or
		// inetOrgPerson, with posixAccount, which all three have
		user, err := users.CreateUser(ctx, "alice", userAttrs("alice", "first Passw0rd!"), true)
		require.NoError(t, err)
		classes := user.GetAll("objectClass")
		if server.ActiveDirectory {
			assert.Contains(t, classes, "user")
			assert.Equal(t, types.Ptr("alice"), user.Get("cn"))
			assert.Equal(t, types.Ptr("alice"), user.Get("sAMAccountName"))
			assert.Equal(t, types.Ptr("512"), user.Get("userAccountControl"), "enabled")
		} else {
			assert.Contains(t, classes, "inetOrgPerson")
			assert.Equal(t, types.Ptr("alice"), user.Get("uid"))
		}
		assert.Contains(t, classes, "posixAccount")
		require.NotNil(t, user.Get("uidNumber"))
		assert.Equal(t, user.Get("uidNumber"), user.Get("gidNumber"), "allocated")

		// The password binds
		_, err = users.Bind(ctx, user.DN, "first Passw0rd!")
		assert.NoError(t, err)

		// Get, and list
		got, err := users.GetUser(ctx, "alice")
		require.NoError(t, err)
		assert.Equal(t, user.DN, got.DN)
		list, err := users.ListUsers(ctx, schema.ObjectListRequest{})
		require.NoError(t, err)
		assert.Equal(t, uint64(1), list.Count)

		// Rename, by its naming attribute, and update
		naming := "uid"
		if server.ActiveDirectory {
			naming = "cn"
		}
		updated, err := users.UpdateUser(ctx, "alice", schema.Attrs{naming: {"alicia"}, "description": {"Renamed"}})
		require.NoError(t, err)
		assert.Equal(t, types.Ptr("Renamed"), updated.Get("description"))
		_, err = users.GetUser(ctx, "alice")
		assert.ErrorIs(t, err, httpresponse.ErrNotFound)
		got, err = users.GetUser(ctx, "alicia")
		require.NoError(t, err)
		assert.Equal(t, updated.DN, got.DN)

		// Delete
		deleted, err := users.DeleteUser(ctx, "alicia")
		require.NoError(t, err)
		assert.Equal(t, updated.DN, deleted.DN)
		_, err = users.GetUser(ctx, "alicia")
		assert.ErrorIs(t, err, httpresponse.ErrNotFound)
	})
}

func Test_UserErrors(t *testing.T) {
	test.ForEach(t, func(t *testing.T, ctx context.Context, server test.Server, m *manager.Manager) {
		users := usersIn(t, ctx, server, m)
		_, err := users.CreateUser(ctx, "bob", userAttrs("bob", "first Passw0rd!"), true)
		require.NoError(t, err)

		_, err = users.CreateUser(ctx, "bob", userAttrs("bob", "first Passw0rd!"), true)
		assert.ErrorIs(t, err, httpresponse.ErrConflict, "exists")
		_, err = users.CreateUser(ctx, "", userAttrs("bob", "first Passw0rd!"), false)
		assert.ErrorIs(t, err, httpresponse.ErrBadRequest, "no name")
		_, err = users.GetUser(ctx, "missing")
		assert.ErrorIs(t, err, httpresponse.ErrNotFound)
		_, err = users.DeleteUser(ctx, "missing")
		assert.ErrorIs(t, err, httpresponse.ErrNotFound)

		attrs := userAttrs("carol", "first Passw0rd!")
		attrs["gidNumber"] = []string{"5000"}
		_, err = users.CreateUser(ctx, "carol", attrs, true)
		assert.ErrorIs(t, err, httpresponse.ErrBadRequest, "allocate_gid with a gidNumber")

		// Users of a class which isn't a posixAccount have no IDs to allocate
		people := test.Manager(t, ctx, server, manager.WithUserDN(test.OU(t, ctx, m), "person"))
		_, err = people.CreateUser(ctx, "dave", schema.Attrs{"sn": {"Example"}}, true)
		assert.ErrorIs(t, err, httpresponse.ErrBadRequest, "allocate_gid without posixAccount")
		dave, err := people.CreateUser(ctx, "dave", schema.Attrs{"sn": {"Example"}}, false)
		require.NoError(t, err)
		assert.Equal(t, types.Ptr("dave"), dave.Get("cn"), "named by cn")
		assert.Nil(t, dave.Get("uidNumber"))

		// A manager without users
		none, err := manager.New(manager.WithUrl(server.URL), manager.WithBaseDN(server.BaseDN), manager.WithUser(server.BindDN), manager.WithPassword(server.BindPassword), manager.WithSkipVerify())
		require.NoError(t, err)
		require.NoError(t, none.Connect(ctx))
		defer none.Disconnect(ctx)
		_, err = none.ListUsers(ctx, schema.ObjectListRequest{})
		assert.ErrorIs(t, err, httpresponse.ErrNotImplemented)
	})
}

func Test_UserIDs(t *testing.T) {
	test.ForEach(t, func(t *testing.T, ctx context.Context, server test.Server, m *manager.Manager) {
		users := usersIn(t, ctx, server, m)

		// Each user has the next ID, and one which is set is kept
		a, err := users.CreateUser(ctx, "a", userAttrs("a", "first Passw0rd!"), true)
		require.NoError(t, err)
		b, err := users.CreateUser(ctx, "b", userAttrs("b", "first Passw0rd!"), true)
		require.NoError(t, err)
		first, err := strconv.Atoi(*a.Get("uidNumber"))
		require.NoError(t, err)
		assert.GreaterOrEqual(t, first, schema.InitialUID)
		assert.Equal(t, strconv.Itoa(first+1), *b.Get("uidNumber"))

		attrs := userAttrs("c", "first Passw0rd!")
		attrs["uidNumber"] = []string{"9999"}
		attrs["gidNumber"] = []string{"9999"}
		c, err := users.CreateUser(ctx, "c", attrs, false)
		require.NoError(t, err)
		assert.Equal(t, types.Ptr("9999"), c.Get("uidNumber"))
	})
}
