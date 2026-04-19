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
	"testing"

	// Packages
	jwt "github.com/golang-jwt/jwt/v5"
	jwk "github.com/lestrrat-go/jwx/v2/jwk"
	manager "github.com/mutablelogic/go-auth/auth/manager"
	oidc "github.com/mutablelogic/go-auth/auth/oidc"
	localprovider "github.com/mutablelogic/go-auth/auth/provider/local"
	authcrypto "github.com/mutablelogic/go-auth/crypto"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestWithIssuer(t *testing.T) {
	t.Run("RejectsEmptyIssuer", func(t *testing.T) {
		mgr, err := manager.New(t.Context(), shared.PoolConn, manager.WithIssuer("   "))
		require.Error(t, err)
		assert.Nil(t, mgr)
		assert.EqualError(t, err, "bad parameter: issuer is required")
	})

	t.Run("UsesExplicitIssuerWithoutLocalProvider", func(t *testing.T) {
		mgr := newCustomSchemaManagerWithOpts(t, "auth_test_oidc_explicit_issuer", manager.WithIssuer("https://issuer.example.test/api"))

		issuer, err := mgr.OIDCIssuer()
		require.NoError(t, err)
		assert.Equal(t, "https://issuer.example.test/api", issuer)

		cfg, err := mgr.OIDCConfig(nil)
		require.NoError(t, err)
		assert.Equal(t, "https://issuer.example.test/api", cfg.Issuer)
	})

	t.Run("ExplicitIssuerOverridesLocalProviderIssuer", func(t *testing.T) {
		key, err := authcrypto.GeneratePrivateKey()
		require.NoError(t, err)

		provider, err := localprovider.New("https://provider.example.test/api", key)
		require.NoError(t, err)

		mgr := newCustomSchemaManagerWithOpts(
			t,
			"auth_test_oidc_issuer_override",
			manager.WithIssuer("https://explicit.example.test/api"),
			manager.WithProvider(provider),
		)

		issuer, err := mgr.OIDCIssuer()
		require.NoError(t, err)
		assert.Equal(t, "https://explicit.example.test/api", issuer)
	})

	t.Run("UsesSpecificSignerByKeyID", func(t *testing.T) {
		primaryKey, err := authcrypto.GeneratePrivateKey()
		require.NoError(t, err)
		secondaryKey, err := authcrypto.GeneratePrivateKey()
		require.NoError(t, err)

		mgr := newCustomSchemaManagerWithOpts(
			t,
			"auth_test_oidc_signers",
			manager.WithIssuer("https://issuer.example.test/api"),
			manager.WithSigner("primary", primaryKey),
			manager.WithSigner("secondary", secondaryKey),
		)

		token, err := mgr.OIDCSign(jwt.MapClaims{"iss": "https://issuer.example.test/api", "sub": "alice"})
		require.NoError(t, err)

		kid, err := oidc.ExtractKeyID(token)
		require.NoError(t, err)
		assert.Equal(t, "secondary", kid)

		claims, err := mgr.OIDCVerify(token, "https://issuer.example.test/api")
		require.NoError(t, err)
		assert.Equal(t, "alice", claims["sub"])

		legacyToken, err := oidc.SignTokenWithKeyID("primary", primaryKey, jwt.MapClaims{"iss": "https://issuer.example.test/api", "sub": "bob"})
		require.NoError(t, err)

		claims, err = mgr.OIDCVerify(legacyToken, "https://issuer.example.test/api")
		require.NoError(t, err)
		assert.Equal(t, "bob", claims["sub"])

		jwks, err := mgr.OIDCJWKSet()
		require.NoError(t, err)
		_, ok := jwks.LookupKeyID("primary")
		assert.True(t, ok)
		entry, ok := jwks.LookupKeyID("secondary")
		require.True(t, ok)
		alg, ok := entry.Get(jwk.AlgorithmKey)
		require.True(t, ok)
		assert.Equal(t, oidc.SigningAlgorithm, alg.(interface{ String() string }).String())
	})
}
