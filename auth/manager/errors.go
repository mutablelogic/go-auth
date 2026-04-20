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

package manager

import (
	"errors"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	pg "github.com/mutablelogic/go-pg"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Normalize database errors and check for known database errors, converting them to
// auth errors as appropriate
func dbErr(err error) error {
	if err == nil {
		return nil
	} else {
		err = pg.NormalizeError(err)
	}

	var authErr auth.Err
	switch {
	case errors.As(err, &authErr):
		return err
	case errors.Is(err, pg.ErrNotFound):
		return auth.ErrNotFound.With(err)
	case errors.Is(err, pg.ErrConflict):
		return auth.ErrConflict.With(err)
	case errors.Is(err, pg.ErrBadParameter):
		return auth.ErrBadParameter.With(err)
	case pg.IsDatabaseError(err):
		return auth.ErrInternalServerError.With(err)
	default:
		return err
	}
}
