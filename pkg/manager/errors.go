package manager

import (
	"errors"

	// Packages
	auth "github.com/djthorpe/go-auth"
	pg "github.com/mutablelogic/go-pg"
)

func dbErr(err error) error {
	if err == nil {
		return nil
	}
	err = pg.NormalizeError(err)

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
