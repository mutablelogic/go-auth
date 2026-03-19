package manager

import (
	"errors"

	// Packages
	auth "github.com/djthorpe/go-auth"
	pgx "github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	pg "github.com/mutablelogic/go-pg"
)

func dbErr(err error) error {
	if err == nil {
		return nil
	}
	var authErr auth.Err
	if errors.As(err, &authErr) {
		return err
	}
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, pg.ErrNotFound) {
		return auth.ErrNotFound.With(err)
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			return auth.ErrConflict.With(pgErr.Message)
		case "23503", "23502", "22P02", "22007", "22008":
			return auth.ErrBadParameter.With(pgErr.Message)
		default:
			return auth.ErrInternalServerError.With(pgErr.Message)
		}
	}

	return err
}
