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
	"net/url"
	"strconv"
	"strings"
	"testing"

	// Packages
	schema "github.com/djthorpe/go-auth/schema/ldap"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	assert "github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLDAPUserCRUDIntegration(t *testing.T) {
	forEachLDAPIntegrationServer(t, func(t *testing.T, ctx context.Context, server ldapIntegrationServer, manager *Manager) {
		requireLDAPIntegrationCRUD(t, server)

		allocateGID := containsFold(manager.users.ObjectClass, "posixAccount")
		user, err := manager.CreateUser(ctx, "alice", newIntegrationUserAttrs(manager, "alice", "Alice Example", "secret-one"), allocateGID)
		require.NoError(t, err)
		require.NotNil(t, user)

		namingAttr := userNamingAttribute(manager.users.ObjectClass)
		if value := user.Get(namingAttr); assert.NotNil(t, value) {
			assert.Equal(t, "alice", *value)
		}

		if containsFold(manager.users.ObjectClass, "posixAccount") {
			if uid := user.Get("uidNumber"); assert.NotNil(t, uid) {
				assert.Equal(t, strconv.Itoa(schema.InitialUID), *uid)
			}
			if gid := user.Get("gidNumber"); assert.NotNil(t, gid) {
				assert.Equal(t, strconv.Itoa(schema.InitialUID), *gid)
			}
		}

		got, err := manager.GetUser(ctx, "alice")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, user.DN, got.DN)

		f := "(" + namingAttr + "=alice)"
		list, err := manager.ListUsers(ctx, schema.ObjectListRequest{Filter: &f})
		require.NoError(t, err)
		require.NotNil(t, list)
		assert.NotZero(t, list.Count)

		newName := "alice2"
		attrs := url.Values{}
		attrs.Set(namingAttr, newName)
		if strings.EqualFold(namingAttr, "cn") {
			attrs.Set("cn", newName)
		} else {
			attrs.Set("cn", "Alice Updated")
		}

		updated, err := manager.UpdateUser(ctx, "alice", attrs)
		require.NoError(t, err)
		require.NotNil(t, updated)

		_, err = manager.GetUser(ctx, "alice")
		require.Error(t, err)
		assert.ErrorIs(t, err, httpresponse.ErrNotFound)

		got, err = manager.GetUser(ctx, newName)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, updated.DN, got.DN)

		deleted, err := manager.DeleteUser(ctx, newName)
		require.NoError(t, err)
		require.NotNil(t, deleted)
		assert.Equal(t, updated.DN, deleted.DN)

		_, err = manager.GetUser(ctx, newName)
		require.Error(t, err)
		assert.ErrorIs(t, err, httpresponse.ErrNotFound)
	})
}

func TestLDAPUserGroupMembershipIntegration(t *testing.T) {
	forEachLDAPIntegrationServer(t, func(t *testing.T, ctx context.Context, server ldapIntegrationServer, manager *Manager) {
		requireLDAPIntegrationCRUD(t, server)

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
