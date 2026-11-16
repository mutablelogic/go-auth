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

// Package store has the interfaces of what an identity is exchanged with:
// a hook, which allows it, or refuses it, the users, which say who it is,
// and the scopes they have, and the sessions, which they're signed in
// with, and the exchanger, which exchanges an identity for a session.
package store

import (
	"context"

	// Packages
	schema "github.com/mutablelogic/go-auth/auth/schema"
)

///////////////////////////////////////////////////////////////////////////////
// INTERFACES

// Hook is user-defined: it says whether an identity can be exchanged for
// a session, such as only one with an email address at a domain, and
// refuses one with an error, such as forbidden
type Hook func(ctx context.Context, identity *schema.Identity) error

// UserStore says who an identity is, and the scopes they have
type UserStore interface {
	// User returns the user an identity is, or not found, when it isn't
	// one of the store's users
	User(ctx context.Context, identity *schema.Identity) (*schema.User, error)

	// Scopes returns the scopes a user has
	Scopes(ctx context.Context, user *schema.User) ([]string, error)
}

// SessionStore keeps sessions, by a hash of their tokens, which aren't
// kept
type SessionStore interface {
	// Create keeps a new session, whose ID and creation are set, and
	// returns its token, which is only returned now
	Create(ctx context.Context, session schema.Session) (*schema.SessionToken, error)

	// Session returns the session of a token, or not authorized, when there
	// isn't one, or it's expired
	Session(ctx context.Context, token string) (*schema.Session, error)

	// Revoke removes the session with the ID, or returns not found
	Revoke(ctx context.Context, id string) error
}
