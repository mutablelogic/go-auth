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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	// Packages
	goauth "github.com/mutablelogic/go-auth"
	httpclient "github.com/mutablelogic/go-auth/auth/httpclient"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
	oauth2 "golang.org/x/oauth2"
)

func Test_Tokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth", "tokens.json")
	tokens, err := httpclient.NewTokens(path)
	require.NoError(t, err)

	// None, without the file
	_, err = tokens.Get("http://localhost:8084/api")
	assert.ErrorIs(t, err, goauth.ErrNotFound)

	// A token, by its endpoint, with or without a slash, in a file only its
	// owner can read
	expiry := time.Now().Add(time.Hour).Round(time.Second)
	require.NoError(t, tokens.Set("http://localhost:8084/api/", &oauth2.Token{AccessToken: "one", TokenType: "Bearer", Expiry: expiry}))
	token, err := tokens.Get("http://localhost:8084/api")
	require.NoError(t, err)
	assert.Equal(t, "one", token.AccessToken)
	assert.True(t, token.Expiry.Equal(expiry))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	info, err = os.Stat(filepath.Dir(path))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())

	// Another endpoint's, which outlasts one that's expired, which is
	// removed when another is kept
	require.NoError(t, tokens.Set("http://other/api", &oauth2.Token{AccessToken: "old", Expiry: time.Now().Add(-time.Minute)}))
	require.NoError(t, tokens.Set("http://third/api", &oauth2.Token{AccessToken: "three"}))
	_, err = tokens.Get("http://other/api")
	assert.ErrorIs(t, err, goauth.ErrNotFound)
	token, err = tokens.Get("http://localhost:8084/api")
	require.NoError(t, err)
	assert.Equal(t, "one", token.AccessToken)

	// Forgotten
	require.NoError(t, tokens.Delete("http://localhost:8084/api"))
	assert.ErrorIs(t, tokens.Delete("http://localhost:8084/api"), goauth.ErrNotFound)
	_, err = tokens.Get("http://localhost:8084/api")
	assert.ErrorIs(t, err, goauth.ErrNotFound)
	assert.Error(t, tokens.Set("http://x", nil))
}

func Test_TokensConcurrent(t *testing.T) {
	// Tokens of their own, as other processes have, which keep tokens at
	// once, lose none
	path := filepath.Join(t.TempDir(), "auth", "tokens.json")
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tokens, err := httpclient.NewTokens(path)
			require.NoError(t, err)
			require.NoError(t, tokens.Set(fmt.Sprintf("http://server%d/api", i), &oauth2.Token{AccessToken: "token"}))
		}()
	}
	wg.Wait()
	tokens, err := httpclient.NewTokens(path)
	require.NoError(t, err)
	for i := range 16 {
		_, err := tokens.Get(fmt.Sprintf("http://server%d/api", i))
		assert.NoError(t, err, i)
	}
}

func Test_TokensPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("modes don't say who can read files")
	}
	// Not in a directory which others can read, or write
	dir := filepath.Join(t.TempDir(), "auth")
	require.NoError(t, os.Mkdir(dir, 0o755))
	tokens, err := httpclient.NewTokens(filepath.Join(dir, "tokens.json"))
	require.NoError(t, err)
	assert.ErrorIs(t, tokens.Set("http://x/api", &oauth2.Token{AccessToken: "token"}), goauth.ErrBadParameter)
	_, err = tokens.Get("http://x/api")
	assert.ErrorIs(t, err, goauth.ErrBadParameter)
	require.NoError(t, os.Chmod(dir, 0o700))
	assert.NoError(t, tokens.Set("http://x/api", &oauth2.Token{AccessToken: "token"}))
}
