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

package internal

import (
	"errors"
	"strings"

	// Packages
	auth "github.com/djthorpe/go-auth"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
)

func HTTPError(err error) error {
	var authErr auth.Err
	if !errors.As(err, &authErr) {
		return err
	}
	reason := strings.TrimPrefix(err.Error(), authErr.Error()+": ")
	switch authErr {
	case auth.ErrNotFound:
		return httpresponse.ErrNotFound.With(reason)
	case auth.ErrBadParameter:
		return httpresponse.ErrBadRequest.With(reason)
	case auth.ErrConflict:
		return httpresponse.ErrConflict.With(reason)
	case auth.ErrNotImplemented:
		return httpresponse.ErrNotImplemented.With(reason)
	case auth.ErrServiceUnavailable:
		return httpresponse.ErrServiceUnavailable.With(reason)
	case auth.ErrInternalServerError:
		return httpresponse.ErrInternalError.With(reason)
	case auth.ErrInvalidProvider:
		return httpresponse.ErrNotAuthorized.With(reason)
	case auth.ErrForbidden:
		return httpresponse.ErrForbidden.With(reason)
	default:
		return httpresponse.ErrInternalError.With(reason)
	}
}
