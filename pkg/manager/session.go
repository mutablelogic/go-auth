package manager

import (
	"context"

	// Packages
	auth "github.com/djthorpe/go-auth"
	schema "github.com/djthorpe/go-auth/schema"
	uuid "github.com/google/uuid"
	pg "github.com/mutablelogic/go-pg"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// GetSession returns a session by ID.
func (m *Manager) GetSession(ctx context.Context, id schema.SessionID) (*schema.Session, error) {
	var session schema.Session
	if err := m.PoolConn.Get(ctx, &session, id); err != nil {
		return nil, dbErr(err)
	}
	return types.Ptr(session), nil
}

// RevokeSession marks a session as revoked and returns the updated session
// record.
func (m *Manager) RevokeSession(ctx context.Context, id schema.SessionID) (*schema.Session, error) {
	var session schema.Session
	if err := m.PoolConn.Update(ctx, &session, revokeSessionSelector(id), nil); err != nil {
		return nil, dbErr(err)
	}
	return types.Ptr(session), nil
}

// RefreshSession validates an existing session, extends its expiry according
// to the manager refresh policy, and returns the owning user together with the
// refreshed session record.
func (m *Manager) RefreshSession(ctx context.Context, id schema.SessionID) (*schema.User, *schema.Session, error) {
	var session schema.Session

	// Update the session expiry
	if err := m.PoolConn.With("expires_in", types.Ptr(m.sessionttl)).Get(ctx, &session, refreshSessionSelector(id)); err != nil {
		return nil, nil, dbErr(err)
	}

	// Return the user associated with the session
	user, err := m.GetUser(ctx, session.User)
	if err != nil {
		return nil, nil, err
	}

	// Return the user associated with the session and the session
	return user, types.Ptr(session), nil
}

// CleanupSessions deletes revoked or expired sessions and returns the deleted
// session rows.
func (m *Manager) CleanupSessions(ctx context.Context) ([]schema.Session, error) {
	var result cleanupSessionList
	if err := m.PoolConn.List(ctx, &result, cleanupSessionSelector(m.cleanuplimit)); err != nil {
		return nil, dbErr(err)
	}
	return []schema.Session(result), nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE TYPES

type refreshSessionSelector schema.SessionID
type revokeSessionSelector schema.SessionID
type cleanupSessionSelector int
type cleanupSessionList []schema.Session

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func (id refreshSessionSelector) Select(bind *pg.Bind, op pg.Op) (string, error) {
	bind.Set("id", uuid.UUID(id))
	switch op {
	case pg.Get:
		return bind.Query("session.refresh"), nil
	default:
		return "", auth.ErrNotImplemented.Withf("unsupported RefreshSession operation %q", op)
	}
}

func (id revokeSessionSelector) Select(bind *pg.Bind, op pg.Op) (string, error) {
	bind.Set("id", uuid.UUID(id))
	switch op {
	case pg.Update:
		return bind.Query("session.revoke"), nil
	default:
		return "", auth.ErrNotImplemented.Withf("unsupported RevokeSession operation %q", op)
	}
}

func (limit cleanupSessionSelector) Select(bind *pg.Bind, op pg.Op) (string, error) {
	switch op {
	case pg.List:
		bind.Set("cleanup_limit", int(limit))
		return bind.Query("session.cleanup"), nil
	default:
		return "", auth.ErrNotImplemented.Withf("unsupported CleanupSessions operation %q", op)
	}
}

func (list *cleanupSessionList) Scan(row pg.Row) error {
	var session schema.Session
	if err := session.Scan(row); err != nil {
		return err
	}
	*list = append(*list, session)
	return nil
}
