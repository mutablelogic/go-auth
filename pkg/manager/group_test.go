package manager_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	// Packages
	auth "github.com/djthorpe/go-auth"
	schema "github.com/djthorpe/go-auth/schema"
	pg "github.com/mutablelogic/go-pg"
	types "github.com/mutablelogic/go-server/pkg/types"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_group_001(t *testing.T) {
	t.Run("CreateGetUpdateDeleteGroup", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)
		enabled := true
		id := fmt.Sprintf("group_%d", time.Now().UnixNano())

		created, err := m.CreateGroup(context.Background(), schema.GroupInsert{
			ID: id,
			GroupMeta: schema.GroupMeta{
				Description: types.Ptr("Administrators"),
				Enabled:     &enabled,
				Scopes:      []string{"user.read", "user.write"},
				Meta:        map[string]any{"team": "auth"},
			},
		})
		require.NoError(err)
		require.NotNil(created)
		assert.Equal(id, created.ID)
		require.NotNil(created.Description)
		assert.Equal("Administrators", *created.Description)
		require.NotNil(created.Enabled)
		assert.True(*created.Enabled)
		assert.Equal([]string{"user.read", "user.write"}, created.Scopes)
		assert.Equal("auth", created.Meta["team"])

		fetched, err := m.GetGroup(context.Background(), id)
		require.NoError(err)
		require.NotNil(fetched)
		assert.Equal(created.ID, fetched.ID)
		require.NotNil(fetched.Description)
		assert.Equal(*created.Description, *fetched.Description)
		require.NotNil(fetched.Enabled)
		assert.Equal(*created.Enabled, *fetched.Enabled)
		assert.Equal(created.Scopes, fetched.Scopes)
		assert.Equal(created.Meta, fetched.Meta)

		disabled := false
		updated, err := m.UpdateGroup(context.Background(), id, schema.GroupMeta{
			Description: types.Ptr("Platform Administrators"),
			Enabled:     &disabled,
			Scopes:      []string{"user.read"},
			Meta:        map[string]any{"team": "platform", "owner": true},
		})
		require.NoError(err)
		require.NotNil(updated)
		assert.Equal(id, updated.ID)
		require.NotNil(updated.Description)
		assert.Equal("Platform Administrators", *updated.Description)
		require.NotNil(updated.Enabled)
		assert.False(*updated.Enabled)
		assert.Equal([]string{"user.read"}, updated.Scopes)
		assert.Equal("platform", updated.Meta["team"])
		assert.Equal(true, updated.Meta["owner"])

		refetched, err := m.GetGroup(context.Background(), id)
		require.NoError(err)
		require.NotNil(refetched)
		assert.Equal(updated.ID, refetched.ID)
		assert.Equal(*updated.Description, *refetched.Description)
		assert.Equal(*updated.Enabled, *refetched.Enabled)
		assert.Equal(updated.Scopes, refetched.Scopes)
		assert.Equal(updated.Meta, refetched.Meta)

		deleted, err := m.DeleteGroup(context.Background(), id)
		require.NoError(err)
		require.NotNil(deleted)
		assert.Equal(updated.ID, deleted.ID)
		require.NotNil(deleted.Description)
		assert.Equal(*updated.Description, *deleted.Description)
		require.NotNil(deleted.Enabled)
		assert.Equal(*updated.Enabled, *deleted.Enabled)
		assert.Equal(updated.Scopes, deleted.Scopes)
		assert.Equal(updated.Meta, deleted.Meta)

		fetched, err = m.GetGroup(context.Background(), id)
		require.Error(err)
		assert.Nil(fetched)
		assert.True(errors.Is(err, auth.ErrNotFound))
	})

	t.Run("CreateGroupDefaultsAndValidation", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)
		id := fmt.Sprintf("team_%d", time.Now().UnixNano())

		created, err := m.CreateGroup(context.Background(), schema.GroupInsert{ID: id})
		require.NoError(err)
		require.NotNil(created)
		assert.Equal(id, created.ID)
		assert.Nil(created.Description)
		require.NotNil(created.Enabled)
		assert.True(*created.Enabled)
		assert.Empty(created.Scopes)
		assert.Empty(created.Meta)

		created, err = m.CreateGroup(context.Background(), schema.GroupInsert{ID: "1invalid"})
		require.Error(err)
		assert.Nil(created)
		assert.True(errors.Is(err, auth.ErrBadParameter))
	})

	t.Run("ListGroups", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)
		enabled := true

		fixtures := []schema.GroupInsert{
			{ID: "charlie", GroupMeta: schema.GroupMeta{Description: types.Ptr("Charlie"), Enabled: &enabled}},
			{ID: "alpha", GroupMeta: schema.GroupMeta{Description: types.Ptr("Alpha"), Enabled: &enabled}},
			{ID: "bravo", GroupMeta: schema.GroupMeta{Description: types.Ptr("Bravo"), Enabled: &enabled}},
		}
		for _, fixture := range fixtures {
			created, err := m.CreateGroup(context.Background(), fixture)
			require.NoError(err)
			require.NotNil(created)
		}

		limit := uint64(2)
		listed, err := m.ListGroups(context.Background(), schema.GroupListRequest{
			OffsetLimit: pg.OffsetLimit{Offset: 1, Limit: &limit},
		})
		require.NoError(err)
		require.NotNil(listed)
		assert.Equal(uint(3), listed.Count)
		assert.Equal(uint64(1), listed.Offset)
		require.NotNil(listed.Limit)
		assert.Equal(uint64(2), *listed.Limit)
		require.Len(listed.Body, 2)
		assert.Equal("bravo", listed.Body[0].ID)
		assert.Equal("charlie", listed.Body[1].ID)

		largeLimit := uint64(10)
		clamped, err := m.ListGroups(context.Background(), schema.GroupListRequest{
			OffsetLimit: pg.OffsetLimit{Limit: &largeLimit},
		})
		require.NoError(err)
		require.NotNil(clamped)
		assert.Equal(uint(3), clamped.Count)
		require.NotNil(clamped.Limit)
		assert.Equal(uint64(3), *clamped.Limit)
		require.Len(clamped.Body, 3)
		assert.Equal("alpha", clamped.Body[0].ID)
		assert.Equal("bravo", clamped.Body[1].ID)
		assert.Equal("charlie", clamped.Body[2].ID)
	})

	t.Run("GetUpdateDeleteMissingGroup", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)

		group, err := m.GetGroup(context.Background(), "missing_group")
		require.Error(err)
		assert.Nil(group)
		assert.True(errors.Is(err, auth.ErrNotFound))

		group, err = m.UpdateGroup(context.Background(), "missing_group", schema.GroupMeta{Description: types.Ptr("Missing")})
		require.Error(err)
		assert.Nil(group)
		assert.True(errors.Is(err, auth.ErrNotFound))

		group, err = m.DeleteGroup(context.Background(), "missing_group")
		require.Error(err)
		assert.Nil(group)
		assert.True(errors.Is(err, auth.ErrNotFound))
	})
}
