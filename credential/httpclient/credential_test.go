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

package httpclient_test

import (
	"context"
	"encoding/json"
	"testing"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	credential "github.com/mutablelogic/go-auth/credential"
	envcredential "github.com/mutablelogic/go-auth/credential/env"
	filecredential "github.com/mutablelogic/go-auth/credential/file"
	httpclient "github.com/mutablelogic/go-auth/credential/httpclient"
	httphandler "github.com/mutablelogic/go-auth/credential/httphandler"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	test "github.com/mutablelogic/go-server/test"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

const (
	passphrase = "test passphrase"
)

// newClient returns a client of a test server, which serves the handlers,
// and checks every request and response against the OpenAPI specification
func newClient(t *testing.T, register func(*testing.T) *test.Server) (*httpclient.Client, *test.Server) {
	t.Helper()
	s := register(t)
	c, err := httpclient.New(s.URL + test.Prefix)
	require.NoError(t, err)
	return c, s
}

func Test_Manager(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir()
	mgr, err := filecredential.New(path, filecredential.WithPassphrase(1, passphrase))
	require.NoError(t, err)
	c, _ := newClient(t, func(t *testing.T) *test.Server {
		return test.NewServer(t, httphandler.RegisterManagerHandlers(mgr, false))
	})

	t.Run("Set", func(t *testing.T) {
		stored, err := c.SetCredential(ctx, credential.CredentialSet{Key: "token", Credentials: json.RawMessage(`"secret"`)})
		require.NoError(t, err)
		assert.Equal(t, "token", stored.Key)
		_, err = c.SetCredential(ctx, credential.CredentialSet{Key: "object", Credentials: json.RawMessage(`{"user":"admin"}`)})
		require.NoError(t, err)
		_, err = c.SetCredential(ctx, credential.CredentialSet{Key: "bad key", Credentials: json.RawMessage(`"x"`)})
		assert.ErrorIs(t, err, auth.ErrBadParameter)
	})

	t.Run("List", func(t *testing.T) {
		list, err := c.ListCredentials(ctx)
		require.NoError(t, err)
		assert.Equal(t, uint64(2), list.Count)
		require.Len(t, list.Body, 2)
		assert.Equal(t, "object", list.Body[0].Key)
		assert.Equal(t, "token", list.Body[1].Key)
	})

	t.Run("Description", func(t *testing.T) {
		// The description is set with the value, and listed, and kept when
		// the value is replaced without one
		description := "The API token"
		stored, err := c.SetCredential(ctx, credential.CredentialSet{Key: "token", Credentials: json.RawMessage(`"secret"`), Description: &description})
		require.NoError(t, err)
		assert.Equal(t, "The API token", stored.Description)
		_, err = c.SetCredential(ctx, credential.CredentialSet{Key: "token", Credentials: json.RawMessage(`"secret"`)})
		require.NoError(t, err)
		meta, err := c.GetCredentialMeta(ctx, "token")
		require.NoError(t, err)
		assert.Equal(t, "The API token", meta.Description)
	})

	t.Run("Meta", func(t *testing.T) {
		meta, err := c.GetCredentialMeta(ctx, "token")
		require.NoError(t, err)
		assert.Equal(t, "token", meta.Key)
		assert.False(t, meta.UpdatedAt.IsZero())
		_, err = c.GetCredentialMeta(ctx, "missing")
		assert.ErrorIs(t, err, auth.ErrNotFound)
	})

	t.Run("Get", func(t *testing.T) {
		var value string
		require.NoError(t, c.GetCredential(ctx, "token", passphrase, &value))
		assert.Equal(t, "secret", value)

		var object map[string]string
		require.NoError(t, c.GetCredential(ctx, "object", passphrase, &object))
		assert.Equal(t, map[string]string{"user": "admin"}, object)

		var raw json.RawMessage
		require.NoError(t, c.GetCredential(ctx, "object", passphrase, &raw))
		assert.JSONEq(t, `{"user":"admin"}`, string(raw))
	})

	t.Run("GetRefused", func(t *testing.T) {
		var value string
		err := c.GetCredential(ctx, "token", "wrong", &value)
		assert.ErrorIs(t, err, auth.ErrForbidden)
		assert.EqualError(t, err, "forbidden: invalid passphrase")
		var response httpresponse.ErrResponse
		assert.ErrorAs(t, err, &response, "the API's error is wrapped")
		assert.Equal(t, 403, response.Code)
		assert.ErrorIs(t, c.GetCredential(ctx, "missing", passphrase, &value), auth.ErrNotFound)
		assert.Empty(t, value)
	})

	t.Run("Rotate", func(t *testing.T) {
		assert.ErrorIs(t, c.RotateCredential(ctx, "token"), auth.ErrNotModified)
		assert.ErrorIs(t, c.RotateCredential(ctx, "missing"), auth.ErrNotFound)

		// With a new passphrase, it's rotated
		v2, err := filecredential.New(path, filecredential.WithPassphrase(1, passphrase), filecredential.WithPassphrase(2, "second passphrase"))
		require.NoError(t, err)
		c2, _ := newClient(t, func(t *testing.T) *test.Server {
			return test.NewServer(t, httphandler.RegisterManagerHandlers(v2, false))
		})
		require.NoError(t, c2.RotateCredential(ctx, "token"))
		var value string
		require.NoError(t, c2.GetCredential(ctx, "token", "second passphrase", &value))
		assert.Equal(t, "secret", value)
	})

	t.Run("Delete", func(t *testing.T) {
		require.NoError(t, c.DeleteCredential(ctx, "token"))
		assert.ErrorIs(t, c.DeleteCredential(ctx, "token"), auth.ErrNotFound)
		_, err := c.GetCredentialMeta(ctx, "token")
		assert.ErrorIs(t, err, auth.ErrNotFound)
	})
}

func Test_Provider(t *testing.T) {
	// A provider which can't store credentials, such as the environment,
	// returns ErrNotImplemented, and has no route which returns a value
	ctx := context.Background()
	t.Setenv("GOAUTH_TEST_CLIENT", "secret")
	c, s := newClient(t, func(t *testing.T) *test.Server {
		return test.NewServer(t, httphandler.RegisterProviderHandlers(envcredential.New(), false))
	})
	_, err := c.SetCredential(ctx, credential.CredentialSet{Key: "GOAUTH_TEST_CLIENT", Credentials: json.RawMessage(`"x"`)})
	assert.ErrorIs(t, err, auth.ErrNotImplemented)

	var value string
	assert.ErrorIs(t, c.GetCredential(ctx, "GOAUTH_TEST_CLIENT", passphrase, &value), auth.ErrNotFound)
	assert.Empty(t, value)
	s.Reset()
}
