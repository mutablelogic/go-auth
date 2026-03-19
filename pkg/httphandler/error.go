package httphandler

import (
	"errors"

	// Packages
	auth "github.com/djthorpe/go-auth"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
)

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// httpErr converts an auth.Err to an httpresponse.Err, preserving the
// original error message. Unknown error codes map to 500.
func httpErr(err error) error {
	var authErr auth.Err
	if !errors.As(err, &authErr) {
		return err
	}
	switch authErr {
	case auth.ErrNotFound:
		return httpresponse.ErrNotFound.With(err)
	case auth.ErrBadParameter:
		return httpresponse.ErrBadRequest.With(err)
	case auth.ErrConflict:
		return httpresponse.ErrConflict.With(err)
	case auth.ErrNotImplemented:
		return httpresponse.ErrNotImplemented.With(err)
	case auth.ErrInternalServerError:
		return httpresponse.ErrInternalError.With(err)
	default:
		return httpresponse.ErrInternalError.With(err)
	}
}
