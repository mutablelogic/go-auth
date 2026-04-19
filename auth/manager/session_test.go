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
	"testing"
	"time"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	manager "github.com/mutablelogic/go-auth/auth/manager"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_session_001(t *testing.T) {
	t.Run("RefreshSessionRotatesCounter", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		sessionTTL := 15 * time.Minute
		refreshTTL := 2 * time.Hour
		m := newCustomSchemaManagerWithOpts(t, "auth_test_session_refresh_rotate", manager.WithTTL(sessionTTL, refreshTTL))

		user, session, err := m.LoginWithIdentity(context.Background(), schema.IdentityInsert{
			IdentityKey:  schema.IdentityKey{Provider: "https://accounts.google.com", Sub: "refresh-rotate-subject"},
			IdentityMeta: schema.IdentityMeta{Email: "refresh.rotate@example.com"},
		}, nil)
		require.NoError(err)
		require.NotNil(user)
		require.NotNil(session)
		assert.Equal(uint64(0), session.RefreshCounter)
		assert.WithinDuration(time.Now().Add(refreshTTL), session.RefreshExpiresAt, 5*time.Second)

		refreshedUser, refreshedSession, err := m.RefreshSession(context.Background(), session.ID, session.RefreshCounter)
		require.NoError(err)
		require.NotNil(refreshedUser)
		require.NotNil(refreshedSession)
		assert.Equal(user.ID, refreshedUser.ID)
		assert.Equal(session.ID, refreshedSession.ID)
		assert.Equal(uint64(1), refreshedSession.RefreshCounter)
		assert.WithinDuration(session.RefreshExpiresAt, refreshedSession.RefreshExpiresAt, time.Second)
		assert.WithinDuration(time.Now().Add(sessionTTL), refreshedSession.ExpiresAt, 5*time.Second)

		_, _, err = m.RefreshSession(context.Background(), session.ID, session.RefreshCounter)
		require.Error(err)
		assert.ErrorIs(err, auth.ErrNotFound)
	})
}
