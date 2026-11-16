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

package schema

import (
	"time"

	// Packages
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// User is who an identity is, which a user store says, or else the
// identity itself
type User struct {
	ID     string   `json:"id" help:"Identifier of the user, which doesn't change"`
	Name   string   `json:"name,omitempty" help:"Name, to show"`
	Email  string   `json:"email,omitempty" help:"Email address"`
	Groups []string `json:"groups,omitempty" help:"Groups the user is in"`
}

// Session is a user's, once they've signed in, with the scopes they had
// then, until it expires, or is revoked
type Session struct {
	ID        string    `json:"id" help:"Identifier of the session, which isn't its token"`
	User      User      `json:"user" help:"Who signed in"`
	Provider  string    `json:"provider" help:"Provider which was signed in with"`
	Scopes    []string  `json:"scopes,omitempty" help:"Scopes the user had, when they signed in"`
	CreatedAt time.Time `json:"created_at" help:"When the session was made"`
	ExpiresAt time.Time `json:"expires_at" help:"When the session expires"`
}

// SessionToken is a new session, with its token, which is only returned
// when it's made, and is what's sent with requests
type SessionToken struct {
	Token string `json:"token" help:"Token of the session, which is only returned once"`
	Session
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Expired returns whether the session has expired, at the time
func (s Session) Expired(now time.Time) bool {
	return !now.Before(s.ExpiresAt)
}

///////////////////////////////////////////////////////////////////////////////
// STRINGIFY

func (u User) String() string {
	return types.Stringify(u)
}

func (s Session) String() string {
	return types.Stringify(s)
}

// String doesn't include the token
func (t SessionToken) String() string {
	return t.Session.String()
}
