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

// Package file keeps sessions in files, in a directory, one for each,
// named by the SHA-256 of its token, which isn't kept, so they last when
// the server restarts, without a database.
package file

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	// Packages
	schema "github.com/mutablelogic/go-auth/auth/schema"
	store "github.com/mutablelogic/go-auth/auth/store"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Sessions keeps sessions in files, in a directory, which only its owner
// can read
type Sessions struct {
	mu  sync.Mutex
	dir string
	now func() time.Time
}

// Opt is an option of the sessions
type Opt func(*Sessions)

var _ store.SessionStore = (*Sessions)(nil)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	// ext is the extension of a session's file
	ext = ".json"

	// tokenBytes is how much is random in a token
	tokenBytes = 32
)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// New returns sessions in the directory, which is made, when it isn't, and
// which only its owner can read or write, so no one else can read sessions,
// or add one, with a token they choose
func New(dir string, opts ...Opt) (*Sessions, error) {
	if dir == "" {
		return nil, httpresponse.ErrBadRequest.With("Sessions need a directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if info, err := os.Stat(dir); err != nil {
		return nil, err
	} else if !info.IsDir() {
		return nil, httpresponse.ErrBadRequest.Withf("%q isn't a directory", dir)
	} else if info.Mode().Perm()&0o077 != 0 {
		return nil, httpresponse.ErrBadRequest.Withf("Sessions' directory %q can be read, or written, by others (%v): only its owner can", dir, info.Mode().Perm())
	}
	self := &Sessions{dir: dir, now: time.Now}
	for _, opt := range opts {
		opt(self)
	}
	return self, nil
}

// WithClock is the time, such as in tests
func WithClock(now func() time.Time) Opt {
	return func(s *Sessions) {
		s.now = now
	}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Create keeps a new session, with a new token, whose hash is its ID and
// file name, and removes those which have expired
func (s *Sessions) Create(_ context.Context, session schema.Session) (*schema.SessionToken, error) {
	data := make([]byte, tokenBytes)
	if _, err := rand.Read(data); err != nil {
		return nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(data)
	session.ID = hash(token)
	if session.CreatedAt.IsZero() {
		session.CreatedAt = s.now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	if err := s.write(session); err != nil {
		return nil, err
	}
	return &schema.SessionToken{Token: token, Session: session}, nil
}

// Session returns the session of the token, or not authorized, when there
// isn't one, or it's expired
func (s *Sessions) Session(_ context.Context, token string) (*schema.Session, error) {
	if token == "" {
		return nil, httpresponse.ErrNotAuthorized.With("No session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	session, err := s.read(hash(token))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, httpresponse.ErrNotAuthorized.With("The session isn't valid, or has ended")
	} else if err != nil {
		return nil, err
	} else if session.Expired(s.now()) {
		return nil, httpresponse.ErrNotAuthorized.With("The session has expired")
	}
	return session, nil
}

// Revoke removes the session with the ID, or returns not found
func (s *Sessions) Revoke(_ context.Context, id string) error {
	if !validID(id) {
		return httpresponse.ErrNotFound.Withf("No session %q", id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(s.path(id)); errors.Is(err, fs.ErrNotExist) {
		return httpresponse.ErrNotFound.Withf("No session %q", id)
	} else if err != nil {
		return err
	}
	return nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// hash is the ID of a token's session: the hex of its SHA-256
func hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// validID returns whether the ID is a session's, which is a hash, so it's a
// file in the directory, and nothing else
func validID(id string) bool {
	if len(id) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

// path is the file of the session with the ID
func (s *Sessions) path(id string) string {
	return filepath.Join(s.dir, id+ext)
}

// read returns the session with the ID
func (s *Sessions) read(id string) (*schema.Session, error) {
	data, err := os.ReadFile(s.path(id))
	if err != nil {
		return nil, err
	}
	var session schema.Session
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}
	return &session, nil
}

// write writes the session to its file, which only its owner can read, all
// at once, so it's never read half written
func (s *Sessions) write(session schema.Session) error {
	data, err := json.Marshal(session)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, ".session-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path(session.ID))
}

// prune removes the sessions which have expired, or can't be read
func (s *Sessions) prune() {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	now := s.now()
	for _, entry := range entries {
		id, ok := strings.CutSuffix(entry.Name(), ext)
		if !ok || !validID(id) {
			continue
		}
		if session, err := s.read(id); err != nil || session.Expired(now) {
			_ = os.Remove(s.path(id))
		}
	}
}
