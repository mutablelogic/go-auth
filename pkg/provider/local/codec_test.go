package local

import (
	"crypto/rsa"
	"testing"

	// Packages
	authcrypto "github.com/djthorpe/go-auth/pkg/crypto"
	jwt "github.com/golang-jwt/jwt/v5"
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
