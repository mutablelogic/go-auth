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

package middleware

import (
	"testing"

	schema "github.com/djthorpe/go-auth/schema"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_policy_001(t *testing.T) {
	t.Run("MatchUserRejectsNilUser", func(t *testing.T) {
		assert := assert.New(t)

		err := MatchScopes("auth:user:read").MatchUser(nil)

		assert.EqualError(err, "user is required")
	})

	t.Run("MatchUserAllowsUserWithRequiredScopes", func(t *testing.T) {
		require := require.New(t)

		user := &schema.User{Scopes: []string{"auth:user:read", "auth:group:write"}}

		err := MatchScopes("auth:user:read", "auth:group:write").MatchUser(user)

		require.NoError(err)
	})
}
