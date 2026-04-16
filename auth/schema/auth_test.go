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
	"errors"
	"strings"
	"testing"

	// Packages
	uuid "github.com/google/uuid"
	auth "github.com/mutablelogic/go-auth"
	oidc "github.com/mutablelogic/go-auth/auth/oidc"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_ExtractIssuer(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		issuer, err := oidc.ExtractIssuer("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSJ9.")
		require.NoError(t, err)
		assert.Equal(t, "https://issuer.example.com", issuer)
	})

	t.Run("InvalidJWT", func(t *testing.T) {
		_, err := oidc.ExtractIssuer("not-a-jwt")
		require.Error(t, err)
		assert.True(t, errors.Is(err, auth.ErrBadParameter))
	})

	t.Run("MissingIssuer", func(t *testing.T) {
		_, err := oidc.ExtractIssuer("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30.")
		require.Error(t, err)
		assert.True(t, errors.Is(err, auth.ErrBadParameter))
	})
}

func Test_auth_001(t *testing.T) {
	t.Run("PublicClientConfigurationsString", func(t *testing.T) {
		assert := assert.New(t)

		text := (PublicClientConfigurations{
			"local":  {Issuer: "https://issuer.example.com"},
			"google": {Issuer: "https://accounts.google.com", ClientID: "client-123"},
		}).String()

		assert.Contains(text, "issuer.example.com")
		assert.Contains(text, "client-123")
	})

	t.Run("NewUserInfo", func(t *testing.T) {
		assert := assert.New(t)

		assert.Nil(NewUserInfo(nil))

		id := UserID(uuid.New())
		userinfo := NewUserInfo(&User{
			ID:     id,
			Scopes: []string{"openid", "profile"},
			UserMeta: UserMeta{
				Name:   "Alice Example",
				Email:  "alice@example.com",
				Groups: []string{"admins"},
			},
		})

		if assert.NotNil(userinfo) {
			assert.Equal(id, userinfo.Sub)
			assert.Equal("Alice Example", userinfo.Name)
			assert.Equal("alice@example.com", userinfo.Email)
			assert.Equal([]string{"admins"}, userinfo.Groups)
			assert.Equal([]string{"openid", "profile"}, userinfo.Scopes)
		}
	})

	t.Run("AuthorizationCodeRequestValidate", func(t *testing.T) {
		assert := assert.New(t)

		req := AuthorizationCodeRequest{Provider: "local", Code: "code-123", RedirectURL: "https://client.example.com/callback"}
		assert.NoError(req.Validate())

		err := (&AuthorizationCodeRequest{Code: "code-123", RedirectURL: "https://client.example.com/callback"}).Validate()
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrInvalidProvider)
		assert.True(strings.Contains(err.Error(), "provider is required"))

		err = (&AuthorizationCodeRequest{Provider: "local", RedirectURL: "https://client.example.com/callback"}).Validate()
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)
		assert.True(strings.Contains(err.Error(), "code is required"))

		err = (&AuthorizationCodeRequest{Provider: "local", Code: "code-123"}).Validate()
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)
		assert.True(strings.Contains(err.Error(), "redirect_url is required"))
	})
}
