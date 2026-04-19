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
	"errors"
	"testing"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_UserGroups_001(t *testing.T) {
	t.Run("AddMissingGroupReturnsNotFound", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)
		_, err := m.CreateGroup(context.Background(), schema.GroupInsert{ID: "staff"})
		require.NoError(err)

		user, err := m.CreateUser(context.Background(), schema.UserMeta{
			Name:   "Joiner",
			Email:  "joiner@example.com",
			Groups: []string{"staff"},
		}, nil)
		require.NoError(err)
		require.NotNil(user)
		assert.Equal([]string{"staff"}, user.Groups)

		updated, err := m.AddUserGroups(context.Background(), user.ID, []string{"xxxx"})
		require.Error(err)
		assert.Nil(updated)
		assert.ErrorIs(err, auth.ErrNotFound)
		assert.Contains(err.Error(), `group "xxxx" not found`)

		fetched, err := m.GetUser(context.Background(), user.ID)
		require.NoError(err)
		require.NotNil(fetched)
		assert.Equal([]string{"staff"}, fetched.Groups)
	})

	t.Run("CreateUserWithMissingGroupReturnsNotFound", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		created, err := newTestManager(t).CreateUser(context.Background(), schema.UserMeta{
			Name:   "Missing Group",
			Email:  "missing-group@example.com",
			Groups: []string{"xxxx"},
		}, nil)
		require.Error(err)
		assert.Nil(created)
		assert.True(errors.Is(err, auth.ErrNotFound))
		assert.Contains(err.Error(), `group "xxxx" not found`)
	})
}
