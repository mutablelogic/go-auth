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

package schema

import (
	"encoding/json"
	"testing"
	"time"

	// Packages
	auth "github.com/djthorpe/go-auth"
	uuid "github.com/google/uuid"
	pg "github.com/mutablelogic/go-pg"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_session_schema_001(t *testing.T) {
	t.Run("SessionIDFromString", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		uid := uuid.New()
		id, err := SessionIDFromString(uid.String())
		require.NoError(err)
		assert.Equal(SessionID(uid), id)

		_, err = SessionIDFromString(uuid.Nil.String())
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)
	})

	t.Run("SessionIDJSON", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		id := SessionID(uuid.New())
		data, err := json.Marshal(id)
		require.NoError(err)

		var roundtrip SessionID
		require.NoError(json.Unmarshal(data, &roundtrip))
		assert.Equal(id, roundtrip)

		err = json.Unmarshal([]byte(`"not-a-uuid"`), &roundtrip)
		assert.Error(err)

		err = json.Unmarshal([]byte(`"00000000-0000-0000-0000-000000000000"`), &roundtrip)
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)
	})

	t.Run("SessionIDText", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		uid := uuid.New()
		var roundtrip SessionID
		require.NoError(roundtrip.UnmarshalText([]byte(uid.String())))
		assert.Equal(SessionID(uid), roundtrip)

		text, err := roundtrip.MarshalText()
		require.NoError(err)
		assert.Equal(uid.String(), string(text))

		err = roundtrip.UnmarshalText([]byte("not-a-uuid"))
		assert.Error(err)

		err = roundtrip.UnmarshalText([]byte(uuid.Nil.String()))
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)
	})

	t.Run("SessionIDSelect", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		bind := pg.NewBind()
		query, err := SessionID(uuid.New()).Select(bind, pg.Get)
		require.NoError(err)
		assert.NotEmpty(query)

		_, err = SessionID(uuid.New()).Select(pg.NewBind(), pg.Update)
		require.NoError(err)
		_, err = SessionID(uuid.New()).Select(pg.NewBind(), pg.Delete)
		require.NoError(err)
		_, err = SessionID(uuid.New()).Select(pg.NewBind(), pg.None)
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrNotImplemented)
	})

	t.Run("SessionScan", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		sessionID := SessionID(uuid.New())
		userID := UserID(uuid.New())
		expiresAt := time.Now().UTC().Add(time.Hour)
		createdAt := time.Now().UTC().Add(-time.Hour)
		revokedAt := time.Now().UTC()

		var session Session
		err := session.Scan(mockRow{values: []any{sessionID, userID, expiresAt, createdAt, &revokedAt}})
		require.NoError(err)
		assert.Equal(sessionID, session.ID)
		assert.Equal(userID, session.User)
		assert.Equal(expiresAt, session.ExpiresAt)
		assert.Equal(createdAt, session.CreatedAt)
		require.NotNil(session.RevokedAt)
		assert.Equal(revokedAt, *session.RevokedAt)
	})

	t.Run("SessionInsertInsertAndUpdate", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		ttl := time.Minute
		insert := SessionInsert{User: UserID(uuid.New()), ExpiresIn: &ttl}
		bind := pg.NewBind("schema", DefaultSchema)
		query, err := insert.Insert(bind)
		require.NoError(err)
		assert.NotEmpty(query)

		patchBind := pg.NewBind()
		require.NoError(insert.Update(patchBind))
		assert.True(patchBind.Has("patch"))
	})

	t.Run("SessionInsertValidation", func(t *testing.T) {
		assert := assert.New(t)

		ttl := time.Minute
		_, err := (SessionInsert{ExpiresIn: &ttl}).Insert(pg.NewBind())
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)

		_, err = (SessionInsert{User: UserID(uuid.New())}).Insert(pg.NewBind())
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)
	})

	t.Run("SessionInsertRejectsInvalidTTL", func(t *testing.T) {
		assert := assert.New(t)
		invalid := time.Duration(0)
		_, err := (SessionInsert{User: UserID(uuid.New()), ExpiresIn: &invalid}).Insert(pg.NewBind("schema", DefaultSchema))
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)
	})

	t.Run("SessionMetaInsertUnsupported", func(t *testing.T) {
		assert := assert.New(t)
		_, err := (SessionMeta{}).Insert(pg.NewBind())
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrNotImplemented)
	})

	t.Run("SessionMetaUpdate", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		ttl := time.Minute
		revokedAt := time.Now().UTC()
		bind := pg.NewBind()
		require.NoError((SessionMeta{ExpiresIn: &ttl, RevokedAt: &revokedAt}).Update(bind))
		assert.True(bind.Has("patch"))
		patch, ok := bind.Get("patch").(string)
		require.True(ok)
		assert.Contains(patch, "expires_at = NOW() + ")
		assert.Contains(patch, "revoked_at = ")

		zero := time.Time{}
		bind = pg.NewBind()
		require.NoError((SessionMeta{RevokedAt: &zero}).Update(bind))
		patch, ok = bind.Get("patch").(string)
		require.True(ok)
		assert.Contains(patch, "revoked_at = NULL")
	})

	t.Run("SessionMetaUpdateInvalidTTL", func(t *testing.T) {
		assert := assert.New(t)
		invalid := time.Duration(0)
		err := (SessionMeta{ExpiresIn: &invalid}).Update(pg.NewBind())
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)
	})

	t.Run("SessionMetaUpdateNoFields", func(t *testing.T) {
		assert := assert.New(t)
		err := (SessionMeta{}).Update(pg.NewBind())
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)
	})
}
