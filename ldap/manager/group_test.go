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
	"slices"
	"strconv"
	"strings"
	"testing"

	// Packages
	ldapv3 "github.com/go-ldap/ldap/v3"
	manager "github.com/mutablelogic/go-auth/ldap/manager"
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	test "github.com/mutablelogic/go-auth/ldap/test"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

// groupsIn returns a manager whose users and groups are in new
// organizational units of the test's
func groupsIn(t *testing.T, ctx context.Context, server test.Server, m *manager.Manager) *manager.Manager {
	t.Helper()
	return test.Manager(t, ctx, server, manager.WithUserDN(test.OU(t, ctx, m)), manager.WithGroupDN(test.OU(t, ctx, m)))
}

// isMember returns how many times the user is in the group: in member or
// uniqueMember, by DN, and in memberUid, by name
func isMember(group, user *schema.Object, name string) (dn, uid int) {
	for _, attr := range []string{"member", "uniqueMember"} {
		for _, value := range group.GetAll(attr) {
			a, errA := ldapv3.ParseDN(value)
			b, errB := ldapv3.ParseDN(user.DN)
			if errA == nil && errB == nil && a.EqualFold(b) {
				dn++
			}
		}
	}
	for _, value := range group.GetAll("memberUid") {
		if value == name {
			uid++
		}
	}
	return dn, uid
}

func Test_Group(t *testing.T) {
	test.ForEach(t, func(t *testing.T, ctx context.Context, server test.Server, m *manager.Manager) {
		groups := groupsIn(t, ctx, server, m)

		group, err := groups.CreateGroup(ctx, "eng", schema.Attrs{"description": {"Engineering"}})
		require.NoError(t, err)
		assert.Equal(t, types.Ptr("eng"), group.Get("cn"))
		assert.Equal(t, types.Ptr("Engineering"), group.Get("description"))
		classes := group.GetAll("objectClass")
		assert.True(t, slices.ContainsFunc(classes, func(c string) bool { return strings.EqualFold(c, "posixGroup") }), "posixGroup")
		gid, err := strconv.Atoi(*group.Get("gidNumber"))
		require.NoError(t, err)
		assert.GreaterOrEqual(t, gid, schema.InitialGID)

		got, err := groups.GetGroup(ctx, "eng")
		require.NoError(t, err)
		assert.Equal(t, group.DN, got.DN)
		list, err := groups.ListGroups(ctx, schema.ObjectListRequest{})
		require.NoError(t, err)
		assert.Equal(t, uint64(1), list.Count)

		// Rename, and update
		updated, err := groups.UpdateGroup(ctx, "eng", schema.Attrs{"cn": {"engineering"}, "description": {"Renamed"}})
		require.NoError(t, err)
		assert.Equal(t, types.Ptr("Renamed"), updated.Get("description"))
		_, err = groups.GetGroup(ctx, "eng")
		assert.ErrorIs(t, err, httpresponse.ErrNotFound)

		deleted, err := groups.DeleteGroup(ctx, "engineering")
		require.NoError(t, err)
		assert.Equal(t, updated.DN, deleted.DN)
		_, err = groups.GetGroup(ctx, "engineering")
		assert.ErrorIs(t, err, httpresponse.ErrNotFound)
	})
}

func Test_GroupMembers(t *testing.T) {
	test.ForEach(t, func(t *testing.T, ctx context.Context, server test.Server, m *manager.Manager) {
		groups := groupsIn(t, ctx, server, m)
		alice, err := groups.CreateUser(ctx, "alice", userAttrs("alice", "first Passw0rd!"), true)
		require.NoError(t, err)
		bob, err := groups.CreateUser(ctx, "bob", userAttrs("bob", "first Passw0rd!"), true)
		require.NoError(t, err)
		_, err = groups.CreateGroup(ctx, "eng", nil)
		require.NoError(t, err)

		// Add, which is in each of the group's membership attributes once
		group, err := groups.AddGroupUsers(ctx, "eng", "alice")
		require.NoError(t, err)
		dn, uid := isMember(group, alice, "alice")
		assert.Positive(t, dn+uid, "a member")
		assert.LessOrEqual(t, dn, 1)
		assert.LessOrEqual(t, uid, 1)

		// Again, which leaves it as it is, and with others
		group, err = groups.AddGroupUsers(ctx, "eng", "alice", "bob", "bob")
		require.NoError(t, err)
		dn2, uid2 := isMember(group, alice, "alice")
		assert.Equal(t, dn, dn2)
		assert.Equal(t, uid, uid2)
		dn, uid = isMember(group, bob, "bob")
		assert.Positive(t, dn+uid, "bob")

		// Remove, and again
		group, err = groups.RemoveGroupUsers(ctx, "eng", "alice")
		require.NoError(t, err)
		dn, uid = isMember(group, alice, "alice")
		assert.Zero(t, dn+uid, "removed")
		group, err = groups.RemoveGroupUsers(ctx, "eng", "alice")
		require.NoError(t, err)
		dn, uid = isMember(group, bob, "bob")
		assert.Positive(t, dn+uid, "bob stays")

		// Errors
		_, err = groups.AddGroupUsers(ctx, "eng", "missing")
		assert.ErrorIs(t, err, httpresponse.ErrNotFound, "no user")
		_, err = groups.AddGroupUsers(ctx, "missing", "bob")
		assert.ErrorIs(t, err, httpresponse.ErrNotFound, "no group")
		_, err = groups.AddGroupUsers(ctx, "eng")
		assert.ErrorIs(t, err, httpresponse.ErrBadRequest, "no users")
		_, err = groups.CreateGroup(ctx, "eng", nil)
		assert.ErrorIs(t, err, httpresponse.ErrConflict, "exists")
	})
}

func Test_GroupIDs(t *testing.T) {
	test.ForEach(t, func(t *testing.T, ctx context.Context, server test.Server, m *manager.Manager) {
		// Each directory's groups are posixGroups: on their own in OpenLDAP,
		// where it's structural, and with groupOfNames or group in the others
		groups := groupsIn(t, ctx, server, m)

		// Each group has the next ID, and one which is set is kept
		a, err := groups.CreateGroup(ctx, "a", nil)
		require.NoError(t, err)
		b, err := groups.CreateGroup(ctx, "b", nil)
		require.NoError(t, err)
		first, err := strconv.Atoi(*a.Get("gidNumber"))
		require.NoError(t, err)
		assert.GreaterOrEqual(t, first, schema.InitialGID)
		assert.Equal(t, strconv.Itoa(first+1), *b.Get("gidNumber"))

		c, err := groups.CreateGroup(ctx, "c", schema.Attrs{"gidNumber": {"9999"}})
		require.NoError(t, err)
		assert.Equal(t, types.Ptr("9999"), c.Get("gidNumber"))
	})
}

func Test_GroupLastMember(t *testing.T) {
	// A group whose class needs a member, and which doesn't have itself,
	// has itself when its last member is removed
	test.ForEach(t, func(t *testing.T, ctx context.Context, server test.Server, m *manager.Manager) {
		if server.ActiveDirectory {
			t.Skip("Active Directory's groups don't need a member")
		}
		for class, attr := range map[string]string{"groupOfNames": "member", "groupOfUniqueNames": "uniqueMember"} {
			t.Run(class, func(t *testing.T) {
				groups := test.Manager(t, ctx, server, manager.WithUserDN(test.OU(t, ctx, m)), manager.WithGroupDN(test.OU(t, ctx, m), class))
				alice, err := groups.CreateUser(ctx, "alice", userAttrs("alice", "first Passw0rd!"), true)
				require.NoError(t, err)
				group, err := groups.CreateGroup(ctx, "eng", schema.Attrs{attr: {alice.DN}})
				require.NoError(t, err)
				require.Len(t, group.GetAll(attr), 1, "alice alone")

				group, err = groups.RemoveGroupUsers(ctx, "eng", "alice")
				require.NoError(t, err)
				dn, _ := isMember(group, alice, "alice")
				assert.Zero(t, dn, "removed")
				members := group.GetAll(attr)
				require.Len(t, members, 1)
				a, err := ldapv3.ParseDN(members[0])
				require.NoError(t, err)
				b, err := ldapv3.ParseDN(group.DN)
				require.NoError(t, err)
				assert.True(t, a.EqualFold(b), "itself")
			})
		}
	})
}
