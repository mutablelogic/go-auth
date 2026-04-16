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

	// Packages
	auth "github.com/mutablelogic/go-auth"
	pg "github.com/mutablelogic/go-pg"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_meta_001(t *testing.T) {
	t.Run("MetaMapJSONAndStrings", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		var meta MetaMap
		require.NoError(meta.UnmarshalJSON([]byte(`{"name":"Alice","email":"alice@example.com","team":"auth"}`)))
		assert.Equal(MetaMap{"name": "Alice", "email": "alice@example.com", "team": "auth"}, meta)

		assert.NoError(meta.UnmarshalJSON([]byte(`null`)))
		assert.Nil(meta)

		err := meta.UnmarshalJSON([]byte(`{"bad key":true}`))
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)

		text := (MetaMap{"team": "auth"}).String()
		assert.Contains(text, "team")
		assert.Contains(text, "auth")

		redacted := (MetaMap{"name": "Alice", "email": "alice@example.com", "team": "auth"}).RedactedString()
		assert.Contains(redacted, "[redacted]")
		assert.Contains(redacted, "team")
		assert.NotContains(redacted, "alice@example.com")
	})

	t.Run("MetaMapText", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		var meta MetaMap
		require.NoError(meta.UnmarshalText([]byte("team=auth;admin=true")))
		assert.Equal(map[string]any{"team": "auth", "admin": true}, meta.Map())

		require.NoError(meta.UnmarshalText([]byte(`{"team":"platform","priority":1}`)))
		assert.Equal(map[string]any{"team": "platform", "priority": float64(1)}, meta.Map())

		require.NoError(meta.UnmarshalText([]byte(`flag=false;count=2;remove=null;labels=["a","b"];config={"enabled":true};name=plain-text;empty=`)))
		assert.Equal(map[string]any{
			"flag":   false,
			"count":  float64(2),
			"remove": nil,
			"labels": []any{"a", "b"},
			"config": map[string]any{"enabled": true},
			"name":   "plain-text",
			"empty":  "",
		}, meta.Map())

		err := meta.UnmarshalText([]byte("bad key=value"))
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)
	})

	t.Run("MetaMapScanAndValue", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		var meta MetaMap
		require.NoError(meta.Scan([]byte(`{"team":"auth"}`)))
		assert.Equal(MetaMap{"team": "auth"}, meta)

		require.NoError(meta.Scan(`{"count":2}`))
		assert.Equal(float64(2), meta["count"])

		require.NoError(meta.Scan(map[string]any{"enabled": true}))
		assert.Equal(MetaMap{"enabled": true}, meta)

		require.NoError(meta.Scan(nil))
		assert.Nil(meta)

		err := meta.Scan(123)
		assert.EqualError(err, "scan MetaMap: unsupported type int")

		value, err := (MetaMap{"team": "auth", "count": float64(2)}).Value()
		require.NoError(err)
		data, ok := value.([]byte)
		require.True(ok)

		var roundtrip map[string]any
		require.NoError(json.Unmarshal(data, &roundtrip))
		assert.Equal(map[string]any{"team": "auth", "count": float64(2)}, roundtrip)

		value, err = (MetaMap(nil)).Value()
		require.NoError(err)
		assert.Nil(value)
	})

	t.Run("MetaInsertExpr", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		meta, err := metaInsertExpr(map[string]any{
			"team":   "auth",
			"region": nil,
			"admin":  true,
		})
		require.NoError(err)
		assert.Equal(map[string]any{
			"admin": true,
			"team":  "auth",
		}, meta)

		_, err = metaInsertExpr(map[string]any{"bad key": true})
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)
	})

	t.Run("MetaPatchExprValidation", func(t *testing.T) {
		assert := assert.New(t)
		bind := pg.NewBind()

		_, err := metaPatchExpr(bind, "meta", "meta", map[string]any{"bad key": true})
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)
	})
}
