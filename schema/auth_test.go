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
	"testing"

	// Packages
	auth "github.com/djthorpe/go-auth"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
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
