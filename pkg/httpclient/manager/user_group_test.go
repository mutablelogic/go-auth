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

package manager

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	// Packages
	authschema "github.com/djthorpe/go-auth/schema/auth"
	uuid "github.com/google/uuid"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestClientDeleteMethods(t *testing.T) {
	t.Run("DeleteUserHandlesNoContent", func(t *testing.T) {
		require := require.New(t)
		userID := authschema.UserID(uuid.New())

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodDelete, r.Method)
			require.Equal("/user/"+uuid.UUID(userID).String(), r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)
		require.NoError(client.DeleteUser(context.Background(), userID))
	})

	t.Run("DeleteGroupHandlesNoContent", func(t *testing.T) {
		require := require.New(t)
		groupID := "delete-group"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodDelete, r.Method)
			require.Equal("/group/"+groupID, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)
		require.NoError(client.DeleteGroup(context.Background(), groupID))
	})

	t.Run("AddUserGroupsPostsArray", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)
		userID := authschema.UserID(uuid.New())
		var request []string

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodPost, r.Method)
			require.Equal("/user/"+uuid.UUID(userID).String()+"/group", r.URL.Path)
			require.NoError(json.NewDecoder(r.Body).Decode(&request))
			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(authschema.User{ID: userID, UserMeta: authschema.UserMeta{Groups: []string{"admins", "staff"}}}))
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)
		response, err := client.AddUserGroups(context.Background(), userID, []string{"admins", "staff"})
		require.NoError(err)
		require.NotNil(response)
		assert.Equal([]string{"admins", "staff"}, request)
		assert.Equal([]string{"admins", "staff"}, response.Groups)
	})

	t.Run("RemoveUserGroupsDeletesArray", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)
		userID := authschema.UserID(uuid.New())
		var request []string

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodDelete, r.Method)
			require.Equal("/user/"+uuid.UUID(userID).String()+"/group", r.URL.Path)
			require.NoError(json.NewDecoder(r.Body).Decode(&request))
			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(authschema.User{ID: userID, UserMeta: authschema.UserMeta{Groups: []string{"admins"}}}))
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)
		response, err := client.RemoveUserGroups(context.Background(), userID, []string{"staff"})
		require.NoError(err)
		require.NotNil(response)
		assert.Equal([]string{"staff"}, request)
		assert.Equal([]string{"admins"}, response.Groups)
	})

	t.Run("GetUserDecodesEffectiveMetaAndDisabledGroups", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)
		userID := authschema.UserID(uuid.New())

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodGet, r.Method)
			require.Equal("/user/"+uuid.UUID(userID).String(), r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(authschema.User{ID: userID, EffectiveMeta: authschema.MetaMap{"group_admin": "hello"}, DisabledGroups: []string{"disabled-group"}, UserMeta: authschema.UserMeta{Meta: authschema.MetaMap{"source": "local"}, Groups: []string{"admins"}}}))
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)
		response, err := client.GetUser(context.Background(), userID)
		require.NoError(err)
		require.NotNil(response)
		assert.Equal(authschema.MetaMap{"source": "local"}, response.Meta)
		assert.Equal(authschema.MetaMap{"group_admin": "hello"}, response.EffectiveMeta)
		assert.Equal([]string{"admins"}, response.Groups)
		assert.Equal([]string{"disabled-group"}, response.DisabledGroups)
	})
}
