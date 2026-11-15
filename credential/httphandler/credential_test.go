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

package httphandler_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	// Packages
	credential "github.com/mutablelogic/go-auth/credential"
	envcredential "github.com/mutablelogic/go-auth/credential/env"
	filecredential "github.com/mutablelogic/go-auth/credential/file"
	httphandler "github.com/mutablelogic/go-auth/credential/httphandler"
	schema "github.com/mutablelogic/go-server/broadcaster/schema"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	test "github.com/mutablelogic/go-server/test"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

const (
	passphrase = "test passphrase"
)

// decrypt sends the passphrase as text, and returns the status code, the
// response headers and body
func decrypt(t *testing.T, s *test.Server, key, passphrase string) (int, http.Header, []byte) {
	t.Helper()
	return s.Send(t, http.MethodPost, "credential/"+key, http.Header{"Content-Type": {"text/plain"}}, []byte(passphrase))
}

func Test_Manager(t *testing.T) {
	path := t.TempDir()
	mgr, err := filecredential.New(path, filecredential.WithPassphrase(1, passphrase))
	require.NoError(t, err)
	s := test.NewServer(t, httphandler.RegisterManagerHandlers(mgr, false))

	t.Run("Set", func(t *testing.T) {
		var stored credential.Credential
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodPut, "credential", credential.CredentialSet{Key: "token", Credentials: json.RawMessage(`"secret"`)}, &stored))
		assert.Equal(t, "token", stored.Key)
		status, _ := s.Do(t, http.MethodPut, "credential", map[string]any{"key": "object", "credentials": map[string]string{"user": "admin"}})
		require.Equal(t, http.StatusOK, status)
	})

	t.Run("Description", func(t *testing.T) {
		// A description is set with the value, listed, and kept when the
		// value is replaced without one
		var stored credential.Credential
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodPut, "credential", map[string]any{"key": "described", "credentials": "x", "description": " What it's for "}, &stored))
		assert.Equal(t, "What it's for", stored.Description)
		status, _ := s.Do(t, http.MethodPut, "credential", map[string]any{"key": "described", "credentials": "y"})
		require.Equal(t, http.StatusOK, status)
		var meta credential.Credential
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodGet, "credential/described", nil, &meta))
		assert.Equal(t, "What it's for", meta.Description)

		// The description changes without the value, and an empty one
		// removes it
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodPatch, "credential/described", map[string]any{"description": "Another"}, &meta))
		assert.Equal(t, "Another", meta.Description)
		status, _, body := decrypt(t, s, "described", passphrase)
		require.Equal(t, http.StatusOK, status)
		assert.JSONEq(t, `"y"`, string(body), "the value isn't changed")
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodPatch, "credential/described", map[string]any{"description": ""}, &meta))
		var removed credential.Credential
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodGet, "credential/described", nil, &removed))
		assert.Empty(t, removed.Description)
		status, _ = s.Do(t, http.MethodPatch, "credential/missing", map[string]any{"description": "x"})
		assert.Equal(t, http.StatusNotFound, status)
		status, _ = s.Do(t, http.MethodDelete, "credential/described", nil)
		require.Equal(t, http.StatusNoContent, status)
	})

	t.Run("SetInvalid", func(t *testing.T) {
		for _, body := range []any{
			map[string]any{"key": "bad key", "credentials": "x"},
			map[string]any{"key": "token"},
			map[string]any{"key": "token", "credentials": nil},
		} {
			status, _ := s.Do(t, http.MethodPut, "credential", body)
			assert.Equal(t, http.StatusBadRequest, status, body)
		}
	})

	t.Run("List", func(t *testing.T) {
		var list credential.CredentialList
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodGet, "credential", nil, &list))
		assert.Equal(t, uint64(2), list.Count)
		require.Len(t, list.Body, 2)
		assert.Equal(t, "object", list.Body[0].Key)
		assert.Equal(t, "token", list.Body[1].Key)
		assert.False(t, list.Body[1].UpdatedAt.IsZero())
	})

	t.Run("Metadata", func(t *testing.T) {
		status, body := s.Do(t, http.MethodGet, "credential/token", nil)
		require.Equal(t, http.StatusOK, status)
		assert.NotContains(t, string(body), "secret", "the value isn't returned")
		status, _ = s.Do(t, http.MethodGet, "credential/missing", nil)
		assert.Equal(t, http.StatusNotFound, status)
		status, _ = s.Do(t, http.MethodGet, "credential/1bad", nil)
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("Decrypt", func(t *testing.T) {
		status, header, body := decrypt(t, s, "token", passphrase)
		require.Equal(t, http.StatusOK, status, string(body))
		assert.Equal(t, "no-store", header.Get("Cache-Control"))
		assert.JSONEq(t, `"secret"`, string(body))

		status, _, body = decrypt(t, s, "object", passphrase)
		require.Equal(t, http.StatusOK, status)
		assert.JSONEq(t, `{"user":"admin"}`, string(body))
	})

	t.Run("DecryptRefused", func(t *testing.T) {
		// A wrong or empty passphrase, or one with a line ending, is
		// forbidden, and the response isn't cached either
		for _, wrong := range []string{"wrong", "", passphrase + "\n"} {
			status, header, _ := decrypt(t, s, "token", wrong)
			assert.Equal(t, http.StatusForbidden, status, "%q", wrong)
			assert.Equal(t, "no-store", header.Get("Cache-Control"))
		}
		status, _, _ := decrypt(t, s, "missing", passphrase)
		assert.Equal(t, http.StatusNotFound, status)
		status, _, _ = decrypt(t, s, "1bad", passphrase)
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("Rotate", func(t *testing.T) {
		status, _ := s.Do(t, http.MethodPost, "credential/token/rotate", nil)
		assert.Equal(t, http.StatusNotModified, status)
		status, _ = s.Do(t, http.MethodPost, "credential/missing/rotate", nil)
		assert.Equal(t, http.StatusNotFound, status)

		// With a new passphrase, it's rotated, and then decrypted with it
		v2, err := filecredential.New(path, filecredential.WithPassphrase(1, passphrase), filecredential.WithPassphrase(2, "second passphrase"))
		require.NoError(t, err)
		s2 := test.NewServer(t, httphandler.RegisterManagerHandlers(v2, false))
		status, _ = s2.Do(t, http.MethodPost, "credential/token/rotate", nil)
		assert.Equal(t, http.StatusNoContent, status)
		status, _, _ = decrypt(t, s2, "token", passphrase)
		assert.Equal(t, http.StatusForbidden, status)
		status, _, body := decrypt(t, s2, "token", "second passphrase")
		require.Equal(t, http.StatusOK, status)
		assert.JSONEq(t, `"secret"`, string(body))
	})

	t.Run("Delete", func(t *testing.T) {
		status, _ := s.Do(t, http.MethodDelete, "credential/token", nil)
		assert.Equal(t, http.StatusNoContent, status)
		status, _ = s.Do(t, http.MethodDelete, "credential/token", nil)
		assert.Equal(t, http.StatusNotFound, status)
		status, _ = s.Do(t, http.MethodGet, "credential/token", nil)
		assert.Equal(t, http.StatusNotFound, status)
		status, _ = s.Do(t, http.MethodDelete, "credential/1bad", nil)
		assert.Equal(t, http.StatusBadRequest, status)
	})
}

func Test_Provider(t *testing.T) {
	mgr, err := filecredential.New(t.TempDir(), filecredential.WithPassphrase(1, passphrase))
	require.NoError(t, err)
	s := test.NewServer(t, httphandler.RegisterProviderHandlers(mgr, false))

	// Store and decrypt
	status, _ := s.Do(t, http.MethodPut, "credential", credential.CredentialSet{Key: "token", Credentials: json.RawMessage(`"secret"`)})
	require.Equal(t, http.StatusOK, status)
	status, _, body := decrypt(t, s, "token", passphrase)
	require.Equal(t, http.StatusOK, status)
	assert.JSONEq(t, `"secret"`, string(body))

	// But not list, get metadata, delete or rotate, which aren't in the
	// specification, so aren't checked against it
	status, _ = s.Do(t, http.MethodGet, "credential", nil)
	assert.Equal(t, http.StatusMethodNotAllowed, status)
	status, _ = s.Do(t, http.MethodGet, "credential/token", nil)
	assert.Equal(t, http.StatusMethodNotAllowed, status)
	status, _ = s.Do(t, http.MethodDelete, "credential/token", nil)
	assert.Equal(t, http.StatusMethodNotAllowed, status)
	status, _ = s.Do(t, http.MethodPost, "credential/token/rotate", nil)
	assert.Equal(t, http.StatusNotFound, status)
	status, _ = s.Do(t, http.MethodPatch, "credential/token", map[string]any{"description": "x"})
	assert.Equal(t, http.StatusMethodNotAllowed, status)
	s.Reset()

	// The specification only has the provider's operations
	paths := s.Spec().Paths
	require.NotNil(t, paths)
	_, hasRotate := paths.MapOfPathItemValues[test.Prefix+"/credential/{key}/rotate"]
	assert.False(t, hasRotate)
}

func Test_ProviderNoPassphrase(t *testing.T) {
	// A provider which doesn't encrypt with its own passphrases, such as the
	// environment, never returns a value, and can't store credentials
	t.Setenv("GOAUTH_TEST_HTTP", "secret")
	s := test.NewServer(t, httphandler.RegisterProviderHandlers(envcredential.New(), false))
	status, _ := s.Do(t, http.MethodPut, "credential", credential.CredentialSet{Key: "GOAUTH_TEST_HTTP", Credentials: json.RawMessage(`"x"`)})
	assert.Equal(t, http.StatusNotImplemented, status)

	status, _ = s.Do(t, http.MethodPut, "credential", map[string]any{"key": "GOAUTH_TEST_HTTP", "credentials": "x", "description": "d"})
	assert.Equal(t, http.StatusNotImplemented, status, "a provider has no descriptions")

	status, _, _ = decrypt(t, s, "GOAUTH_TEST_HTTP", passphrase)
	assert.Equal(t, http.StatusNotFound, status)
	s.Reset()
}

func Test_Auth(t *testing.T) {
	// With auth, the operations need a registered security scheme
	mgr, err := filecredential.New(t.TempDir(), filecredential.WithPassphrase(1, passphrase))
	require.NoError(t, err)
	router, err := httprouter.NewRouter(context.Background(), http.NewServeMux(), "/api", "", "test", "0.0.0")
	require.NoError(t, err)
	assert.Error(t, httphandler.RegisterManagerHandlers(mgr, true)(router))
}

// publisher records the changes which are published
type publisher struct {
	changes []schema.Change
}

func (p *publisher) Publish(change schema.Change) int {
	p.changes = append(p.changes, change)
	return 0
}

func Test_Publish(t *testing.T) {
	// A change is published after each write which succeeds, by the key,
	// without the value
	mgr, err := filecredential.New(t.TempDir(), filecredential.WithPassphrase(1, passphrase))
	require.NoError(t, err)
	var p publisher
	s := test.NewServer(t, httphandler.RegisterManagerHandlers(mgr, false, httphandler.WithPublisher(&p)))

	status, _ := s.Do(t, http.MethodPut, "credential", map[string]any{"key": "token", "credentials": "secret"})
	require.Equal(t, http.StatusOK, status)
	status, _ = s.Do(t, http.MethodPatch, "credential/token", map[string]any{"description": "d"})
	require.Equal(t, http.StatusOK, status)
	status, _ = s.Do(t, http.MethodPost, "credential/token/rotate", nil)
	require.Equal(t, http.StatusNotModified, status, "nothing changed, so nothing is published")
	status, _ = s.Do(t, http.MethodDelete, "credential/token", nil)
	require.Equal(t, http.StatusNoContent, status)
	status, _ = s.Do(t, http.MethodDelete, "credential/token", nil)
	require.Equal(t, http.StatusNotFound, status, "a failure isn't published")

	assert.Equal(t, []schema.Change{
		{Action: schema.ChangeUpdate, Table: "credential", Row: "token"},
		{Action: schema.ChangeUpdate, Table: "credential", Row: "token"},
		{Action: schema.ChangeDelete, Table: "credential", Row: "token"},
	}, p.changes)
	for _, change := range p.changes {
		assert.Empty(t, change.Data, "no value is published")
	}
}
