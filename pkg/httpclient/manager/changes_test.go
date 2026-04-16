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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	// Packages
	authschema "github.com/mutablelogic/go-auth/schema/auth"
	client "github.com/mutablelogic/go-client"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestClientListenChanges(t *testing.T) {
	t.Run("ListenChangesUsesTextStreamAndBearerToken", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		changes := make(chan authschema.ChangeNotification, 2)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(http.MethodGet, r.Method)
			assert.Equal("/changes", r.URL.Path)
			assert.Equal("text/event-stream", r.Header.Get("Accept"))
			assert.Equal("Bearer local-token", r.Header.Get("Authorization"))

			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)

			_, err := io.WriteString(w, "event: change\ndata: {\"schema\":\"auth\",\"table\":\"user\",\"action\":\"INSERT\"}\n\n")
			assert.NoError(err)
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}))
		defer server.Close()

		mgrClient, err := New(server.URL, client.OptReqToken(client.Token{Scheme: client.Bearer, Value: "local-token"}))
		require.NoError(err)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		done := make(chan error, 1)
		go func() {
			done <- mgrClient.ListenChanges(ctx, func(change authschema.ChangeNotification) error {
				changes <- change
				cancel()
				return io.EOF
			})
		}()

		select {
		case change := <-changes:
			assert.Equal(authschema.ChangeNotification{Schema: "auth", Table: "user", Action: "INSERT"}, change)
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for change notification")
		}

		select {
		case err := <-done:
			require.NoError(err)
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for ListenChanges to exit")
		}
	})

	t.Run("ListenChangesPropagatesCallbackError", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		expected := errors.New("stop stream")
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			_, err := io.WriteString(w, "data: {\"schema\":\"auth\",\"table\":\"group\",\"action\":\"UPDATE\"}\n\n")
			assert.NoError(err)
		}))
		defer server.Close()

		mgrClient, err := New(server.URL)
		require.NoError(err)

		err = mgrClient.ListenChanges(context.Background(), func(change authschema.ChangeNotification) error {
			assert.Equal("group", change.Table)
			return expected
		})

		require.ErrorIs(err, expected)
	})

	t.Run("ListenChangesRequiresCallback", func(t *testing.T) {
		require := require.New(t)

		mgrClient, err := New("https://example.test")
		require.NoError(err)

		err = mgrClient.ListenChanges(context.Background(), nil)
		require.EqualError(err, "change callback is required")
	})

	t.Run("ListenChangesAllowsAdditionalRequestOptions", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal("42", r.Header.Get("Last-Event-ID"))
			assert.Equal("team", r.URL.Query().Get("scope"))
			w.Header().Set("Content-Type", "text/event-stream")
			_, err := fmt.Fprint(w, "data: {\"schema\":\"auth\",\"table\":\"scope\",\"action\":\"DELETE\"}\n\n")
			require.NoError(err)
		}))
		defer server.Close()

		mgrClient, err := New(server.URL)
		require.NoError(err)

		err = mgrClient.ListenChanges(context.Background(), func(change authschema.ChangeNotification) error {
			assert.Equal("DELETE", change.Action)
			return io.EOF
		},
			client.OptReqHeader("Last-Event-ID", "42"),
			client.OptQuery(map[string][]string{"scope": {"team"}}),
		)

		require.NoError(err)
	})
}
