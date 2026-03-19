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
