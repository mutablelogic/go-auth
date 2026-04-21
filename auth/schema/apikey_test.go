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
	"strings"
	"testing"

	// Packages
	uuid "github.com/google/uuid"
	auth "github.com/mutablelogic/go-auth"
	pg "github.com/mutablelogic/go-pg"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_apikey_schema_001(t *testing.T) {
	t.Run("KeyIDFromString", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		uid := uuid.New()
		id, err := KeyIDFromString(uid.String())
		require.NoError(err)
		assert.Equal(KeyID(uid), id)

		_, err = KeyIDFromString(uuid.Nil.String())
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)
	})

	t.Run("KeyIDJSON", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		id := KeyID(uuid.New())
		data, err := json.Marshal(id)
		require.NoError(err)
		assert.Equal(`"`+uuid.UUID(id).String()+`"`, string(data))

		var roundtrip KeyID
		require.NoError(json.Unmarshal(data, &roundtrip))
		assert.Equal(id, roundtrip)

		err = json.Unmarshal([]byte(`"not-a-uuid"`), &roundtrip)
		assert.Error(err)

		err = json.Unmarshal([]byte(`"00000000-0000-0000-0000-000000000000"`), &roundtrip)
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)
	})

	t.Run("KeyIDText", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		uid := uuid.New()
		var roundtrip KeyID
		require.NoError(roundtrip.UnmarshalText([]byte(uid.String())))
		assert.Equal(KeyID(uid), roundtrip)

		text, err := roundtrip.MarshalText()
		require.NoError(err)
		assert.Equal(uid.String(), string(text))

		err = roundtrip.UnmarshalText([]byte("not-a-uuid"))
		assert.Error(err)

		err = roundtrip.UnmarshalText([]byte(uuid.Nil.String()))
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)
	})

	t.Run("KeyJSONUsesUUIDString", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		key := Key{
			ID:    KeyID(uuid.New()),
			User:  UserID(uuid.New()),
			Token: "secret",
			KeyMeta: KeyMeta{
				Name: "test",
			},
		}

		data, err := json.Marshal(key)
		require.NoError(err)

		var decoded map[string]any
		require.NoError(json.Unmarshal(data, &decoded))
		assert.Equal(uuid.UUID(key.ID).String(), decoded["id"])
		assert.Equal(uuid.UUID(key.User).String(), decoded["user"])
	})

	t.Run("KeyListRequestSelectGroupsNonExpiredFilter", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		user := UserID(uuid.New())
		expired := false
		bind := pg.NewBind("schema", DefaultSchema)
		query, err := (KeyListRequest{User: &user, Expired: &expired}).Select(bind, pg.List)
		require.NoError(err)
		assert.NotEmpty(query)

		where, ok := bind.Get("where").(string)
		require.True(ok)
		assert.Contains(where, `apikey."user" = @user AND ((`)
		assert.True(strings.Contains(where, `) IS NULL OR (`))
		assert.True(strings.Contains(where, `) >= NOW())`))

		_, err = (KeyListRequest{}).Select(pg.NewBind(), pg.Get)
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrNotImplemented)
	})
}
