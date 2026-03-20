package manager_test

import (
	"context"
	"testing"

	// Packages
	schema "github.com/djthorpe/go-auth/schema"
	pg "github.com/mutablelogic/go-pg"
	types "github.com/mutablelogic/go-server/pkg/types"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_scope_001(t *testing.T) {
	t.Run("ListScopes", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)
		enabled := true
		disabled := false

		fixtures := []schema.GroupInsert{
			{
				ID: "admins",
				GroupMeta: schema.GroupMeta{
					Description: types.Ptr("Admins"),
					Enabled:     &enabled,
					Scopes:      []string{"user.read", "user.write", "profile.read"},
				},
			},
			{
				ID: "staff",
				GroupMeta: schema.GroupMeta{
					Description: types.Ptr("Staff"),
					Enabled:     &enabled,
					Scopes:      []string{"profile.read", "team.manage"},
				},
			},
			{
				ID: "suspended",
				GroupMeta: schema.GroupMeta{
					Description: types.Ptr("Suspended"),
					Enabled:     &disabled,
					Scopes:      []string{"admin.all"},
				},
			},
		}
		for _, fixture := range fixtures {
			created, err := m.CreateGroup(context.Background(), fixture)
			require.NoError(err)
			require.NotNil(created)
		}

		limit := uint64(3)
		listed, err := m.ListScopes(context.Background(), schema.ScopeListRequest{
			OffsetLimit: pg.OffsetLimit{Offset: 1, Limit: &limit},
		})
		require.NoError(err)
		require.NotNil(listed)
		assert.Equal(uint(5), listed.Count)
		assert.Equal(uint64(1), listed.Offset)
		require.NotNil(listed.Limit)
		assert.Equal(uint64(3), *listed.Limit)
		assert.Equal([]string{"profile.read", "team.manage", "user.read"}, listed.Body)

		filtered, err := m.ListScopes(context.Background(), schema.ScopeListRequest{Q: "user"})
		require.NoError(err)
		require.NotNil(filtered)
		assert.Equal(uint(2), filtered.Count)
		require.Len(filtered.Body, 2)
		assert.Equal([]string{"user.read", "user.write"}, filtered.Body)

		literal, err := m.ListScopes(context.Background(), schema.ScopeListRequest{Q: "%"})
		require.NoError(err)
		require.NotNil(literal)
		assert.Zero(literal.Count)
		assert.Empty(literal.Body)

		largeLimit := uint64(10)
		clamped, err := m.ListScopes(context.Background(), schema.ScopeListRequest{
			OffsetLimit: pg.OffsetLimit{Limit: &largeLimit},
		})
		require.NoError(err)
		require.NotNil(clamped)
		assert.Equal(uint(5), clamped.Count)
		require.NotNil(clamped.Limit)
		assert.Equal(uint64(5), *clamped.Limit)
		assert.Equal([]string{"admin.all", "profile.read", "team.manage", "user.read", "user.write"}, clamped.Body)
	})
}
