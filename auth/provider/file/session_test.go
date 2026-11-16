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

package file_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	// Packages
	file "github.com/mutablelogic/go-auth/auth/provider/file"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_Sessions(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "sessions")
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	sessions, err := file.New(dir, file.WithClock(clock))
	require.NoError(t, err)
	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(), "only its owner's")

	session := schema.Session{User: schema.User{ID: "alice"}, Provider: "google", Scopes: []string{"ldap:read"}, ExpiresAt: now.Add(time.Hour)}
	created, err := sessions.Create(ctx, session)
	require.NoError(t, err)
	assert.NotEmpty(t, created.Token)
	assert.Len(t, created.ID, 64)
	assert.NotEqual(t, created.Token, created.ID)
	assert.Equal(t, now, created.CreatedAt)

	t.Run("ByToken", func(t *testing.T) {
		found, err := sessions.Session(ctx, created.Token)
		require.NoError(t, err)
		assert.Equal(t, created.Session.ID, found.ID)
		assert.Equal(t, []string{"ldap:read"}, found.Scopes)
		_, err = sessions.Session(ctx, "another")
		assert.ErrorIs(t, err, httpresponse.ErrNotAuthorized)
		_, err = sessions.Session(ctx, "")
		assert.ErrorIs(t, err, httpresponse.ErrNotAuthorized)
	})

	t.Run("TokenNotKept", func(t *testing.T) {
		// Only its hash, which is its file's name, and only its owner can
		// read it
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Equal(t, created.ID+".json", entries[0].Name())
		data, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
		require.NoError(t, err)
		assert.NotContains(t, string(data), created.Token)
		info, err := entries[0].Info()
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	})

	t.Run("Restart", func(t *testing.T) {
		again, err := file.New(dir, file.WithClock(clock))
		require.NoError(t, err)
		_, err = again.Session(ctx, created.Token)
		assert.NoError(t, err)
	})

	t.Run("Expiry", func(t *testing.T) {
		short, err := sessions.Create(ctx, schema.Session{User: schema.User{ID: "bob"}, ExpiresAt: now.Add(time.Minute)})
		require.NoError(t, err)
		now = now.Add(2 * time.Minute)
		_, err = sessions.Session(ctx, short.Token)
		assert.ErrorIs(t, err, httpresponse.ErrNotAuthorized)

		// Expired sessions are removed, when another is made
		_, err = sessions.Create(ctx, schema.Session{User: schema.User{ID: "carol"}, ExpiresAt: now.Add(time.Hour)})
		require.NoError(t, err)
		_, err = os.Stat(filepath.Join(dir, short.ID+".json"))
		assert.ErrorIs(t, err, os.ErrNotExist)
		_, err = sessions.Session(ctx, created.Token)
		assert.NoError(t, err, "not those which haven't")
	})

	t.Run("Revoke", func(t *testing.T) {
		require.NoError(t, sessions.Revoke(ctx, created.ID))
		_, err := sessions.Session(ctx, created.Token)
		assert.ErrorIs(t, err, httpresponse.ErrNotAuthorized)
		assert.ErrorIs(t, sessions.Revoke(ctx, created.ID), httpresponse.ErrNotFound)

		// Only a session's ID, not another file
		assert.ErrorIs(t, sessions.Revoke(ctx, "../"+strings.Repeat("0", 61)), httpresponse.ErrNotFound)
	})

	_, err = file.New("")
	assert.ErrorIs(t, err, httpresponse.ErrBadRequest)
}

func Test_SessionsDirectory(t *testing.T) {
	// A directory which others can read, or write, isn't used, so no one
	// else can add a session, with a token they choose
	dir := filepath.Join(t.TempDir(), "open")
	require.NoError(t, os.Mkdir(dir, 0o700))
	require.NoError(t, os.Chmod(dir, 0o770))
	_, err := file.New(dir)
	assert.ErrorIs(t, err, httpresponse.ErrBadRequest)
	require.NoError(t, os.Chmod(dir, 0o700))
	_, err = file.New(dir)
	assert.NoError(t, err)

	// Nor a file
	path := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(path, nil, 0o600))
	_, err = file.New(path)
	assert.Error(t, err)
}

func Test_Consume(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "sessions")
	now := time.Now()
	clock := func() time.Time { return now }
	s, err := file.New(dir, file.WithClock(clock))
	require.NoError(t, err)

	// An ID is consumed once, by another store with the directory too
	require.NoError(t, s.Consume(ctx, "code", now.Add(time.Minute)))
	assert.ErrorIs(t, s.Consume(ctx, "code", now.Add(time.Minute)), httpresponse.ErrConflict)
	other, err := file.New(dir, file.WithClock(clock))
	require.NoError(t, err)
	assert.ErrorIs(t, other.Consume(ctx, "code", now.Add(time.Minute)), httpresponse.ErrConflict)
	require.NoError(t, other.Consume(ctx, "another", now.Add(time.Minute)))

	// Until it expires, when it's removed
	now = now.Add(2 * time.Minute)
	require.NoError(t, s.Consume(ctx, "later", now.Add(time.Minute)))
	entries, err := os.ReadDir(filepath.Join(dir, "consumed"))
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}
