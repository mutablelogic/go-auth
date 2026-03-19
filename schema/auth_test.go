package schema

import (
	"errors"
	"testing"

	auth "github.com/djthorpe/go-auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_jwtIssuer(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		issuer, err := jwtIssuer("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSJ9.")
		require.NoError(t, err)
		assert.Equal(t, "https://issuer.example.com", issuer)
	})

	t.Run("InvalidJWT", func(t *testing.T) {
		_, err := jwtIssuer("not-a-jwt")
		require.Error(t, err)
		assert.True(t, errors.Is(err, auth.ErrBadParameter))
	})

	t.Run("MissingIssuer", func(t *testing.T) {
		_, err := jwtIssuer("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30.")
		require.Error(t, err)
		assert.True(t, errors.Is(err, auth.ErrBadParameter))
	})
}
