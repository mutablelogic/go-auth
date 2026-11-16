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

package store

import (
	"context"
	"errors"
	"time"

	// Packages
	schema "github.com/mutablelogic/go-auth/auth/schema"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Exchanger exchanges an identity for a session: when the hook allows it,
// for the user it is, which a user store says, with their scopes, which
// the session has, until it expires
type Exchanger struct {
	sessions SessionStore
	users    UserStore
	hook     Hook
	ttl      time.Duration
	now      func() time.Time
}

// Opt is an option of an exchanger
type Opt func(*Exchanger) error

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

// DefaultTTL is how long a session lasts, without WithTTL
const DefaultTTL = 24 * time.Hour

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// NewExchanger returns an exchanger, which keeps sessions in the store.
// Without a user store, the user is the identity, without scopes, and
// without a hook, every identity is allowed.
func NewExchanger(sessions SessionStore, opts ...Opt) (*Exchanger, error) {
	if sessions == nil {
		return nil, httpresponse.ErrBadRequest.With("An exchanger needs a session store")
	}
	self := &Exchanger{sessions: sessions, ttl: DefaultTTL, now: time.Now}
	for _, opt := range opts {
		if err := opt(self); err != nil {
			return nil, err
		}
	}
	return self, nil
}

///////////////////////////////////////////////////////////////////////////////
// OPTIONS

// WithUsers says who an identity is, and their scopes, with the store
func WithUsers(users UserStore) Opt {
	return func(e *Exchanger) error {
		e.users = users
		return nil
	}
}

// WithHook allows, or refuses, an identity with the hook, before it's
// exchanged
func WithHook(hook Hook) Opt {
	return func(e *Exchanger) error {
		e.hook = hook
		return nil
	}
}

// WithTTL is how long a session lasts
func WithTTL(ttl time.Duration) Opt {
	return func(e *Exchanger) error {
		if ttl <= 0 {
			return httpresponse.ErrBadRequest.With("A session lasts for some time")
		}
		e.ttl = ttl
		return nil
	}
}

// WithClock is the time, such as in tests
func WithClock(now func() time.Time) Opt {
	return func(e *Exchanger) error {
		e.now = now
		return nil
	}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Exchange exchanges an identity for a session, and returns its token. A
// hook's error refuses it, as does an identity which isn't a user, which
// is forbidden.
func (e *Exchanger) Exchange(ctx context.Context, identity *schema.Identity) (any, error) {
	if identity == nil {
		return nil, httpresponse.ErrBadRequest.With("No identity")
	}
	if e.hook != nil {
		if err := e.hook(ctx, identity); err != nil {
			return nil, err
		}
	}

	// The user, and their scopes, which the user store says, or else the
	// identity, without scopes
	user := &schema.User{ID: identity.Provider + ":" + identity.Subject, Name: identity.Name, Email: identity.Email, Groups: identity.Groups}
	var scopes []string
	if e.users != nil {
		found, err := e.users.User(ctx, identity)
		if errors.Is(err, httpresponse.ErrNotFound) {
			return nil, httpresponse.ErrForbidden.Withf("%s isn't a user", who(identity))
		} else if err != nil {
			return nil, err
		}
		if scopes, err = e.users.Scopes(ctx, found); err != nil {
			return nil, err
		}
		user = found
	}

	now := e.now()
	return e.sessions.Create(ctx, schema.Session{
		User:      *user,
		Provider:  identity.Provider,
		Scopes:    scopes,
		CreatedAt: now,
		ExpiresAt: now.Add(e.ttl),
	})
}

// ResponseSchema is the schema of what an identity is exchanged for, which
// is the response of signing in
func ResponseSchema() *jsonschema.Schema {
	return jsonschema.MustFor[schema.SessionToken]()
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// who is an identity, to say who isn't a user: their email address, or
// else their name, or subject
func who(identity *schema.Identity) string {
	switch {
	case identity.Email != "":
		return identity.Email
	case identity.Name != "":
		return identity.Name
	default:
		return identity.Subject
	}
}
