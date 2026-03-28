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
	"testing"

	// Packages
	auth "github.com/djthorpe/go-auth"
	pg "github.com/mutablelogic/go-pg"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_meta_001(t *testing.T) {
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
