package auth

import (
	"errors"
	"testing"

	// Packages
	auth "github.com/djthorpe/go-auth"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_error_001(t *testing.T) {
	t.Run("MapsAuthErrors", func(t *testing.T) {
		cases := []struct {
			name  string
			input error
			match error
			text  string
		}{
			{"NotFound", auth.ErrNotFound.With("missing"), httpresponse.ErrNotFound, "missing"},
			{"BadParameter", auth.ErrBadParameter.With("bad"), httpresponse.ErrBadRequest, "bad"},
			{"Conflict", auth.ErrConflict.With("dup"), httpresponse.ErrConflict, "dup"},
			{"NotImplemented", auth.ErrNotImplemented.With("todo"), httpresponse.ErrNotImplemented, "todo"},
			{"Internal", auth.ErrInternalServerError.With("boom"), httpresponse.ErrInternalError, "boom"},
			{"InvalidProvider", auth.ErrInvalidProvider.With("provider"), httpresponse.ErrNotAuthorized, "provider"},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				assert := assert.New(t)
				mapped := httpErr(tc.input)
				assert.True(errors.Is(mapped, tc.match))
				assert.Contains(mapped.Error(), tc.text)
			})
		}
	})

	t.Run("PassesThroughUnknownErrors", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		input := errors.New("plain error")
		mapped := httpErr(input)

		require.NotNil(mapped)
		assert.Same(input, mapped)
	})
}
