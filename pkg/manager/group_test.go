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
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_group_001(t *testing.T) {
	t.Run("CreateGroup", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)
		enabled := true
		id := fmt.Sprintf("group_%d", time.Now().UnixNano())

		created, err := m.CreateGroup(context.Background(), schema.GroupInsert{
			ID: id,
			GroupMeta: schema.GroupMeta{
				Description: ptrString("Administrators"),
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

		var fetched schema.Group
		require.NoError(m.Get(context.Background(), &fetched, schema.Group{ID: id}))
		assert.Equal(created.ID, fetched.ID)
		require.NotNil(fetched.Description)
		assert.Equal(*created.Description, *fetched.Description)
		require.NotNil(fetched.Enabled)
		assert.Equal(*created.Enabled, *fetched.Enabled)
		assert.Equal(created.Scopes, fetched.Scopes)
		assert.Equal(created.Meta, fetched.Meta)
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
}

func ptrString(value string) *string {
	return &value
}
