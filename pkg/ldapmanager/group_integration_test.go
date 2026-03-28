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
	"testing"

	// Packages
	schema "github.com/djthorpe/go-auth/schema/ldap"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestLDAPGroupCRUDIntegration(t *testing.T) {
	forEachLDAPIntegrationServer(t, func(t *testing.T, ctx context.Context, _ ldapIntegrationServer, manager *Manager) {
		group, err := manager.CreateGroup(ctx, "eng", url.Values{
			"description": {"Engineering"},
		})
		require.NoError(t, err)
		require.NotNil(t, group)

		if containsFold(manager.groups.ObjectClass, "posixGroup") {
			if gid := group.Get("gidNumber"); assert.NotNil(t, gid) {
				assert.Equal(t, strconv.Itoa(schema.InitialGID), *gid)
			}
		}

		got, err := manager.GetGroup(ctx, "eng")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, group.DN, got.DN)

		f := "(cn=eng)"
		list, err := manager.ListGroups(ctx, schema.ObjectListRequest{Filter: &f})
		require.NoError(t, err)
		require.NotNil(t, list)
		assert.NotZero(t, list.Count)

		updated, err := manager.UpdateGroup(ctx, "eng", url.Values{
			"cn":          {"eng2"},
			"description": {"Engineering Updated"},
		})
		require.NoError(t, err)
		require.NotNil(t, updated)
		assert.Contains(t, updated.DN, "cn=eng2")

		_, err = manager.GetGroup(ctx, "eng")
		require.Error(t, err)
		assert.ErrorIs(t, err, httpresponse.ErrNotFound)

		got, err = manager.GetGroup(ctx, "eng2")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, updated.DN, got.DN)

		deleted, err := manager.DeleteGroup(ctx, "eng2")
		require.NoError(t, err)
		require.NotNil(t, deleted)
		assert.Equal(t, updated.DN, deleted.DN)

		_, err = manager.GetGroup(ctx, "eng2")
		require.Error(t, err)
		assert.ErrorIs(t, err, httpresponse.ErrNotFound)
	})
}
