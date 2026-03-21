package manager

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	// Packages
	authschema "github.com/djthorpe/go-auth/schema"
	pg "github.com/mutablelogic/go-pg"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestClientScopeMethods(t *testing.T) {
	t.Run("ListScopesUsesQueryParameters", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		limit := uint64(3)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodGet, r.Method)
			require.Equal("/scope", r.URL.Path)
			assert.Equal("1", r.URL.Query().Get("offset"))
			assert.Equal("3", r.URL.Query().Get("limit"))
			assert.Equal("user.read", r.URL.Query().Get("q"))

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(authschema.ScopeList{OffsetLimit: pg.OffsetLimit{Offset: 1, Limit: &limit}, Count: 2, Body: []string{"user.read", "user.write"}}))
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)

		response, err := client.ListScopes(context.Background(), authschema.ScopeListRequest{OffsetLimit: pg.OffsetLimit{Offset: 1, Limit: &limit}, Q: "user.read"})
		require.NoError(err)
		require.NotNil(response)
		assert.Equal(uint(2), response.Count)
		assert.Equal(uint64(1), response.Offset)
		require.NotNil(response.Limit)
		assert.Equal(uint64(3), *response.Limit)
		assert.Equal([]string{"user.read", "user.write"}, response.Body)
	})

	t.Run("ListScopesReturnsEmptyList", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodGet, r.Method)
			require.Equal("/scope", r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(authschema.ScopeList{OffsetLimit: pg.OffsetLimit{}, Count: 0, Body: []string{}}))
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)

		response, err := client.ListScopes(context.Background(), authschema.ScopeListRequest{})
		require.NoError(err)
		require.NotNil(response)
		assert.Zero(response.Count)
		assert.Empty(response.Body)
	})
}
