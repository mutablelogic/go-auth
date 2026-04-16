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
	"strings"
	"testing"

	// Packages
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestLDAPObjectCRUDAndPasswordIntegration(t *testing.T) {
	forEachLDAPIntegrationServer(t, func(t *testing.T, ctx context.Context, server ldapIntegrationServer, manager *Manager) {
		created, err := manager.Create(ctx, "ou=projects", url.Values{
			"objectClass": {"top", "organizationalUnit"},
			"ou":          {"projects"},
			"description": {"Projects"},
		})
		require.NoError(t, err)
		require.NotNil(t, created)
		if value := created.Get("ou"); assert.NotNil(t, value) {
			assert.Equal(t, "projects", *value)
		}

		f := "(ou=projects)"
		list, err := manager.List(ctx, schema.ObjectListRequest{Filter: &f})
		require.NoError(t, err)
		require.NotNil(t, list)
		assert.NotZero(t, list.Count)

		got, err := manager.Get(ctx, "ou=projects")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, created.DN, got.DN)

		updated, err := manager.Update(ctx, "ou=projects", url.Values{
			"ou":          {"engineering-projects"},
			"description": {"Engineering Projects"},
		})
		require.NoError(t, err)
		require.NotNil(t, updated)
		assert.Contains(t, strings.ToLower(updated.DN), "ou=engineering-projects")

		_, err = manager.Get(ctx, "ou=projects")
		require.Error(t, err)
		assert.ErrorIs(t, err, httpresponse.ErrNotFound)

		deleted, err := manager.Delete(ctx, "ou=engineering-projects")
		require.NoError(t, err)
		require.NotNil(t, deleted)
		assert.Equal(t, updated.DN, deleted.DN)

		_, err = manager.Get(ctx, "ou=engineering-projects")
		require.Error(t, err)
		assert.ErrorIs(t, err, httpresponse.ErrNotFound)

		if !server.PasswordCompat {
			t.Logf("skipping password checks for %s", server.Name)
			return
		}

		password := "secret-one"
		user, err := manager.CreateUser(ctx, "binduser", newIntegrationUserAttrs(manager, "binduser", "Bind User", password), containsFold(manager.users.ObjectClass, "posixAccount"))
		require.NoError(t, err)
		require.NotNil(t, user)

		relativeDN := integrationUserRelativeDN(manager, "binduser")
		bound, err := manager.Bind(ctx, relativeDN, password)
		require.NoError(t, err)
		require.NotNil(t, bound)
		assert.Equal(t, user.DN, bound.DN)

		newPassword := "secret-two"
		changed, generated, err := manager.ChangePassword(ctx, relativeDN, password, &newPassword)
		require.NoError(t, err)
		require.NotNil(t, changed)
		assert.Equal(t, user.DN, changed.DN)
		assert.Nil(t, generated)

		oldBound, err := manager.Bind(ctx, relativeDN, password)
		if server.PasswordChangeInvalidatesOld {
			require.Error(t, err)
			assert.ErrorIs(t, err, httpresponse.ErrNotAuthorized)
		} else {
			require.NoError(t, err)
			require.NotNil(t, oldBound)
			assert.Equal(t, user.DN, oldBound.DN)
		}

		rebound, err := manager.Bind(ctx, relativeDN, newPassword)
		require.NoError(t, err)
		require.NotNil(t, rebound)
		assert.Equal(t, user.DN, rebound.DN)
	})
}
