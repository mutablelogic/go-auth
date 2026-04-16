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

package auth

import (
	"errors"
	"testing"

	// Packages
	auth "github.com/mutablelogic/go-auth"
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
			{"ServiceUnavailable", auth.ErrServiceUnavailable.With("wait"), httpresponse.ErrServiceUnavailable, "wait"},
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
