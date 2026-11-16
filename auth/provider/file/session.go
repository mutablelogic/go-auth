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
	"strconv"
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
var _ store.Consumer = (*Sessions)(nil)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	// ext is the extension of a session's file
	ext = ".json"

	// tokenBytes is how much is random in a token
	tokenBytes = 32

	// consumed is the directory of the IDs which have been consumed
	consumed = "consumed"

	// keyFile is the file of the key, and keyBytes its size
	keyFile  = "key"
	keyBytes = 32
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

// Consume consumes the ID, until it expires, as a file, named by its hash,
// which is created only when it isn't there, so it's consumed once, by any
// server which shares the directory, or after a restart. Those which have
// expired are removed.
func (s *Sessions) Consume(_ context.Context, id string, expires time.Time) error {
	dir := filepath.Join(s.dir, consumed)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneConsumed(dir)
	f, err := os.OpenFile(filepath.Join(dir, hash(id)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return httpresponse.ErrConflict.With("It's been used")
	} else if err != nil {
		return err
	}
	_, err = f.WriteString(strconv.FormatInt(expires.Unix(), 10))
	return errors.Join(err, f.Close())
}

// Key returns the key of the sessions, of 32 bytes, such as the one which
// seals sign-ins, and OAuth clients' IDs and codes, so they last when the
// server restarts, and servers which share the directory accept each
// other's. It's in the directory, which only its owner can read, out of
// reach of anything else, such as credentials, which could replace it.
// It's made when it isn't there, at once, so when servers make it at the
// same time, there's one, which they all return.
func (s *Sessions) Key() ([]byte, error) {
	path := filepath.Join(s.dir, keyFile)
	if key, err := readKey(path); !errors.Is(err, fs.ErrNotExist) {
		return key, err
	}

	// A new key, written to a file of its own, which is linked as the key,
	// unless there's one, which is returned
	key := make([]byte, keyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(s.dir, ".key-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return nil, err
	}
	if _, err := tmp.WriteString(base64.RawURLEncoding.EncodeToString(key)); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Link(tmp.Name(), path); errors.Is(err, fs.ErrExist) {
		return readKey(path)
	} else if err != nil {
		return nil, err
	}
	return key, nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// readKey returns the key in the file, which only its owner can read
func readKey(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	} else if info.Mode().Perm()&0o077 != 0 {
		return nil, httpresponse.ErrBadRequest.Withf("The key %q can be read, or written, by others (%v): only its owner can", path, info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(key) != keyBytes {
		return nil, httpresponse.ErrBadRequest.Withf("The key %q isn't %d bytes, base64url", path, keyBytes)
	}
	return key, nil
}

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

// pruneConsumed removes the consumed IDs which have expired. One which
// can't be read is kept, as it may be being written.
func (s *Sessions) pruneConsumed(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	now := s.now().Unix()
	for _, entry := range entries {
		if !validID(entry.Name()) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		if expires, err := strconv.ParseInt(string(data), 10, 64); err == nil && now > expires {
			_ = os.Remove(filepath.Join(dir, entry.Name()))
		}
	}
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
