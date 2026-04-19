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
	"context"

	// Packages
	uuid "github.com/google/uuid"
	auth "github.com/mutablelogic/go-auth"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	pg "github.com/mutablelogic/go-pg"
	types "github.com/mutablelogic/go-server/pkg/types"
	attribute "go.opentelemetry.io/otel/attribute"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// GetSession returns a session by ID.
func (m *Manager) GetSession(ctx context.Context, id schema.SessionID) (_ *schema.Session, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "GetSession",
		attribute.String("session", id.String()),
	)
	defer func() { endSpan(err) }()

	var session schema.Session
	if err = m.PoolConn.Get(ctx, &session, id); err != nil {
		err = dbErr(err)
		return nil, err
	}
	return types.Ptr(session), nil
}

// RevokeSession marks a session as revoked and returns the updated session
// record.
func (m *Manager) RevokeSession(ctx context.Context, id schema.SessionID) (_ *schema.Session, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "RevokeSession",
		attribute.String("session", id.String()),
	)
	defer func() { endSpan(err) }()

	var session schema.Session
	if err = m.PoolConn.Update(ctx, &session, revokeSessionSelector(id), nil); err != nil {
		err = dbErr(err)
		return nil, err
	}
	return types.Ptr(session), nil
}

// RefreshSession validates an existing session, extends its expiry according
// to the manager refresh policy, and returns the owning user together with the
// refreshed session record.
func (m *Manager) RefreshSession(ctx context.Context, id schema.SessionID, refreshCounter uint64) (_ *schema.User, _ *schema.Session, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "RefreshSession",
		attribute.String("session", id.String()),
		attribute.Int64("refresh_counter", int64(refreshCounter)),
	)
	defer func() { endSpan(err) }()

	var session schema.Session

	// Update the session expiry
	if err = m.PoolConn.With("expires_in", types.Ptr(m.sessionttl)).Get(ctx, &session, refreshSessionSelector{ID: id, RefreshCounter: refreshCounter}); err != nil {
		err = dbErr(err)
		return nil, nil, err
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
func (m *Manager) CleanupSessions(ctx context.Context) (_ []schema.Session, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "CleanupSessions",
		attribute.Int("cleanup_limit", m.cleanuplimit),
	)
	defer func() { endSpan(err) }()

	var result cleanupSessionList
	if err = m.PoolConn.List(ctx, &result, cleanupSessionSelector(m.cleanuplimit)); err != nil {
		err = dbErr(err)
		return nil, err
	}
	return []schema.Session(result), nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE TYPES

type refreshSessionSelector struct {
	ID             schema.SessionID
	RefreshCounter uint64
}
type revokeSessionSelector schema.SessionID
type cleanupSessionSelector int
type cleanupSessionList []schema.Session

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func (s refreshSessionSelector) Select(bind *pg.Bind, op pg.Op) (string, error) {
	bind.Set("id", uuid.UUID(s.ID))
	bind.Set("refresh_counter", s.RefreshCounter)
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
