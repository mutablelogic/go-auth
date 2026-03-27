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

package webcallback_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	// Packages
	webcallback "github.com/djthorpe/go-auth/pkg/webcallback"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestListenRequiresLoopbackHTTPURL(t *testing.T) {
	_, err := webcallback.New("")
	require.EqualError(t, err, "callback URL is required")

	_, err = webcallback.New("https://127.0.0.1:8085/callback")
	require.EqualError(t, err, "callback URL must use http")

	_, err = webcallback.New("http://example.com:8085/callback")
	require.EqualError(t, err, `callback URL host "example.com" must be loopback`)
}

func TestListenAllocatesPortWhenMissing(t *testing.T) {
	listener, err := webcallback.New("http://localhost/")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(listener.URL(), "http://localhost:"))
	assert.True(t, strings.HasSuffix(listener.URL(), "/"))
}

func TestResultAccessors(t *testing.T) {
	result := webcallback.Result{Query: url.Values{
		"code":  {"abc123"},
		"state": {"state-123"},
	}}

	assert.Equal(t, "abc123", result.Code())
	assert.Equal(t, "state-123", result.State())
}

func TestListenReceivesCallback(t *testing.T) {
	listener, err := webcallback.New("http://127.0.0.1:0/callback")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(listener.URL(), "http://127.0.0.1:"))
	assert.NotContains(t, listener.URL(), ":0/")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resultCh := make(chan *webcallback.Result, 1)
	errCh := make(chan error, 1)
	go func() {
		result, err := listener.Run(ctx)
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- result
	}()
	time.Sleep(20 * time.Millisecond)

	response, err := http.Get(listener.URL() + "?code=abc123&state=state-123")
	require.NoError(t, err)
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, response.StatusCode)
	assert.Contains(t, string(body), "Authentication complete")

	select {
	case err := <-errCh:
		require.NoError(t, err)
	case result := <-resultCh:
		require.NotNil(t, result)
		assert.Equal(t, "abc123", result.Code())
		assert.Equal(t, "state-123", result.State())
		assert.Equal(t, "abc123", result.Query.Get("code"))
		assert.Equal(t, "state-123", result.Query.Get("state"))
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for callback")
	}
}

func TestWaitRespectsContext(t *testing.T) {
	listener, err := webcallback.New("http://127.0.0.1:0/callback")
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	result, err := listener.Run(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Nil(t, result)
}

func TestRunReturnsCallbackError(t *testing.T) {
	listener, err := webcallback.New("http://127.0.0.1:0/callback")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resultCh := make(chan *webcallback.Result, 1)
	errCh := make(chan error, 1)
	go func() {
		result, err := listener.Run(ctx)
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- result
	}()
	time.Sleep(20 * time.Millisecond)

	response, err := http.Get(listener.URL() + "?error=access_denied&error_description=user%20cancelled")
	require.NoError(t, err)
	defer response.Body.Close()

	select {
	case err := <-errCh:
		require.EqualError(t, err, "access_denied: user cancelled")
	case result := <-resultCh:
		t.Fatalf("expected callback error, got result: %#v", result)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for callback error")
	}
}
