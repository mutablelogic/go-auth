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

package local

import (
	"crypto/rsa"
	"testing"

	// Packages
	jwt "github.com/golang-jwt/jwt/v5"
	authcrypto "github.com/mutablelogic/go-auth/crypto"
	require "github.com/stretchr/testify/require"
)

func TestNewCodecValidation(t *testing.T) {
	t.Run("missing issuer", func(t *testing.T) {
		_, err := NewCodec("", nil)
		require.EqualError(t, err, "issuer is required")
	})

	t.Run("missing private key", func(t *testing.T) {
		_, err := NewCodec("http://localhost:8084/api", nil)
		require.EqualError(t, err, "private key is required")
	})
}

func TestCodecRoundTrip(t *testing.T) {
	require := require.New(t)

	key, err := authcrypto.GeneratePrivateKey()
	require.NoError(err)

	codec, err := NewCodec("http://localhost:8084/api", key)
	require.NoError(err)

	issuer, err := codec.Issuer()
	require.NoError(err)
	require.Equal("http://localhost:8084/api", issuer)

	token, err := codec.Sign(jwt.MapClaims{
		"iss": issuer,
		"sub": "local@example.com",
	})
	require.NoError(err)

	claims, err := codec.Verify(token, issuer)
	require.NoError(err)
	require.Equal("local@example.com", claims["sub"])
}

func TestCodecFailures(t *testing.T) {
	t.Run("issuer missing", func(t *testing.T) {
		codec := codec{
			issuer:     "",
			privateKey: &rsa.PrivateKey{},
		}

		_, err := codec.Issuer()
		require.EqualError(t, err, "issuer is not configured")
	})

	t.Run("sign missing key", func(t *testing.T) {
		codec := codec{
			issuer:     "http://localhost:8084/api",
			privateKey: nil,
		}

		_, err := codec.Sign(jwt.MapClaims{})
		require.EqualError(t, err, "private key is required for signing")
	})

	t.Run("verify missing key", func(t *testing.T) {
		codec := codec{
			issuer:     "http://localhost:8084/api",
			privateKey: nil,
		}

		_, err := codec.Verify("token", "issuer")
		require.EqualError(t, err, "private key is required for verification")
	})

	t.Run("issuer value returned", func(t *testing.T) {
		codec := codec{issuer: "http://localhost:8084/api", privateKey: &rsa.PrivateKey{}}
		issuer, err := codec.Issuer()
		require.NoError(t, err)
		require.Equal(t, "http://localhost:8084/api", issuer)
	})
}
