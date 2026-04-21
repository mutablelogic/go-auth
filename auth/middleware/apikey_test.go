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
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	// Packages
	uuid "github.com/google/uuid"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

type stubKeyAuthenticator struct {
	user *schema.UserInfo
	key  *schema.Key
	err  error
}

func (s stubKeyAuthenticator) AuthenticateKey(_ context.Context, token string) (*schema.UserInfo, *schema.Key, error) {
	if token == "" {
		return nil, nil, errors.New("missing token")
	}
	return s.user, s.key, s.err
}

func Test_apikey_001(t *testing.T) {
	t.Run("APIKeyToken", func(t *testing.T) {
		assert := assert.New(t)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		_, ok := apiKeyToken(req)
		assert.False(ok)

		req.Header.Set("X-API-Key", "key-value")
		token, ok := apiKeyToken(req)
		assert.True(ok)
		assert.Equal("key-value", token)
	})

	t.Run("APIKeyAuthNSetsContext", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		user := &schema.UserInfo{Sub: schema.UserID(uuid.New()), Scopes: []string{"auth:key:read"}}
		key := &schema.Key{ID: schema.KeyID(uuid.New()), User: user.Sub, KeyMeta: schema.KeyMeta{Name: "test-key"}}

		handler := APIKeyAuthN(stubKeyAuthenticator{user: user, key: key})(func(w http.ResponseWriter, r *http.Request) {
			gotUser := UserFromContext(r.Context())
			require.NotNil(gotUser)
			assert.Equal(user.Sub, gotUser.Sub)

			gotKey := KeyFromContext(r.Context())
			require.NotNil(gotKey)
			assert.Equal(key.ID, gotKey.ID)
			w.WriteHeader(http.StatusNoContent)
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-API-Key", "key-value")
		res := httptest.NewRecorder()

		handler(res, req)

		require.Equal(http.StatusNoContent, res.Code)
	})

	t.Run("APIKeyAuthNRejectsMissingKey", func(t *testing.T) {
		require := require.New(t)

		handler := APIKeyAuthN(stubKeyAuthenticator{})(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})

		res := httptest.NewRecorder()
		handler(res, httptest.NewRequest(http.MethodGet, "/", nil))

		require.Equal(http.StatusUnauthorized, res.Code)
	})
}
