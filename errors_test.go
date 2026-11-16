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

package auth_test

import (
	"errors"
	"io"
	"testing"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	assert "github.com/stretchr/testify/assert"
)

func Test_ErrWithf(t *testing.T) {
	assert := assert.New(t)

	err := auth.ErrNotFound.Withf("credential %q", "key")
	assert.ErrorIs(err, auth.ErrNotFound)
	assert.Equal(`not found: credential "key"`, err.Error())

	err = auth.ErrInternalServerError.Withf("read %q: %w", "file", io.EOF)
	assert.ErrorIs(err, auth.ErrInternalServerError)
	assert.ErrorIs(err, io.EOF)
	assert.Equal(`internal server error: read "file": EOF`, err.Error())

	var authErr auth.Err
	assert.True(errors.As(err, &authErr))
	assert.Equal(auth.ErrInternalServerError, authErr)
	assert.Equal(`not found: missing`, auth.ErrNotFound.Withf("missing").Error())
}

func Test_ClientError(t *testing.T) {
	// Each auth error, as its HTTP status, is the auth error again
	for _, want := range []auth.Err{auth.ErrBadParameter, auth.ErrInvalidProvider, auth.ErrForbidden, auth.ErrNotFound, auth.ErrConflict, auth.ErrNotImplemented, auth.ErrServiceUnavailable, auth.ErrInternalServerError} {
		var code httpresponse.Err
		if assert.ErrorAs(t, auth.HTTPError(want.With("reason")), &code, want.Error()) {
			assert.ErrorIs(t, auth.ClientError(httpresponse.ErrResponse{Code: int(code), Reason: "reason"}), want, want.Error())
		}
	}
	assert.NoError(t, auth.ClientError(nil))
}
