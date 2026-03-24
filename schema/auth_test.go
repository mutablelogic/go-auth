package schema

import (
	"context"
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

func Test_TokenRequestValidate(t *testing.T) {
	t.Run("MissingProvider", func(t *testing.T) {
		assert := assert.New(t)
		_, err := (&TokenRequest{Token: "abc"}).Validate(context.Background())
		assert.Error(err)
		assert.True(errors.Is(err, auth.ErrInvalidProvider))
	})

	t.Run("MissingToken", func(t *testing.T) {
		assert := assert.New(t)
		_, err := (&TokenRequest{Provider: ProviderOAuth}).Validate(context.Background())
		assert.Error(err)
		assert.True(errors.Is(err, auth.ErrBadParameter))
	})

	t.Run("UnsupportedProvider", func(t *testing.T) {
		assert := assert.New(t)
		_, err := (&TokenRequest{Provider: "nope", Token: "abc"}).Validate(context.Background())
		assert.Error(err)
		assert.True(errors.Is(err, auth.ErrInvalidProvider))
	})
}

func Test_CredentialsRequestValidate(t *testing.T) {
	t.Run("MissingEmail", func(t *testing.T) {
		assert := assert.New(t)
		err := (&CredentialsRequest{}).Validate()
		assert.Error(err)
		assert.True(errors.Is(err, auth.ErrBadParameter))
	})

	t.Run("InvalidEmail", func(t *testing.T) {
		assert := assert.New(t)
		err := (&CredentialsRequest{Email: "not-an-email"}).Validate()
		assert.Error(err)
		assert.True(errors.Is(err, auth.ErrBadParameter))
	})

	t.Run("NormalizesEmail", func(t *testing.T) {
		require := require.New(t)
		req := &CredentialsRequest{Email: "  Alice.Example+test@Example.COM  "}
		require.NoError(req.Validate())
		require.Equal("alice.example+test@example.com", req.Email)
	})
}
