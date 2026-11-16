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

package httpclient

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	// Packages
	goauth "github.com/mutablelogic/go-auth"
	oauth2 "golang.org/x/oauth2"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Tokens keeps a command's tokens, by the endpoint they're for, in a file,
// which only its owner can read, so a command signs in once, and its other
// commands send the token
type Tokens struct {
	mu   sync.Mutex
	path string
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// NewTokens returns the tokens in the file, which is made, with its
// directory, when a token is kept
func NewTokens(path string) (*Tokens, error) {
	if path == "" {
		return nil, goauth.ErrBadParameter.With("tokens need a file")
	}
	return &Tokens{path: path}, nil
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Get returns the token for the endpoint, or not found, when there isn't
// one. It can have expired.
func (t *Tokens) Get(endpoint string) (*oauth2.Token, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	tokens, err := t.read()
	if err != nil {
		return nil, err
	}
	token, ok := tokens[key(endpoint)]
	if !ok {
		return nil, goauth.ErrNotFound.Withf("not signed in to %s", key(endpoint))
	}
	return token, nil
}

// Set keeps the token for the endpoint, replacing any, and removes those
// which have expired
func (t *Tokens) Set(endpoint string, token *oauth2.Token) error {
	if token == nil || token.AccessToken == "" {
		return goauth.ErrBadParameter.With("no token")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	tokens, err := t.read()
	if err != nil {
		return err
	}
	for endpoint, token := range tokens {
		if !token.Valid() {
			delete(tokens, endpoint)
		}
	}
	tokens[key(endpoint)] = token
	return t.write(tokens)
}

// Delete forgets the token for the endpoint, or returns not found
func (t *Tokens) Delete(endpoint string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	tokens, err := t.read()
	if err != nil {
		return err
	} else if _, ok := tokens[key(endpoint)]; !ok {
		return goauth.ErrNotFound.Withf("not signed in to %s", key(endpoint))
	}
	delete(tokens, key(endpoint))
	return t.write(tokens)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// key is an endpoint, without a trailing slash, which tokens are kept by
func key(endpoint string) string {
	return strings.TrimRight(strings.TrimSpace(endpoint), "/")
}

// read returns the tokens, which are none, without the file
func (t *Tokens) read() (map[string]*oauth2.Token, error) {
	tokens := map[string]*oauth2.Token{}
	data, err := os.ReadFile(t.path)
	if errors.Is(err, fs.ErrNotExist) {
		return tokens, nil
	} else if err != nil {
		return nil, err
	} else if err := json.Unmarshal(data, &tokens); err != nil {
		return nil, goauth.ErrBadParameter.Withf("tokens %q: %v", t.path, err)
	}
	return tokens, nil
}

// write writes the tokens to the file, which only its owner can read, in
// a directory only they can, all at once, so it's never read half written
func (t *Tokens) write(tokens map[string]*oauth2.Token) error {
	dir := filepath.Dir(t.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(tokens, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tokens-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), t.path)
}
