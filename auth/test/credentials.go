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

package test

import (
	"context"
	"encoding/json"
	"sync"

	// Packages
	goauth "github.com/mutablelogic/go-auth"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	credential "github.com/mutablelogic/go-auth/credential"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Credentials is a credential provider in memory, such as of providers'
// OAuth clients
type Credentials struct {
	mu     sync.Mutex
	values map[string]json.RawMessage
}

var _ credential.CredentialProvider = (*Credentials)(nil)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// NewCredentials returns credentials, without any
func NewCredentials() *Credentials {
	return &Credentials{values: make(map[string]json.RawMessage)}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// WithClient stores an OAuth client, with its ID and secret, at the key,
// and returns the credentials
func (c *Credentials) WithClient(key, clientID, clientSecret string) *Credentials {
	data, _ := json.Marshal(schema.OAuthClient{ClientID: clientID, ClientSecret: clientSecret})
	_ = c.Set(context.Background(), key, data)
	return c
}

// Get returns the credential at the key, or not found
func (c *Credentials) Get(_ context.Context, key string) (json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	value, ok := c.values[key]
	if !ok {
		return nil, goauth.ErrNotFound.With(key)
	}
	return value, nil
}

// Set stores the credential at the key
func (c *Credentials) Set(_ context.Context, key string, value json.RawMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.values[key] = value
	return nil
}

// Delete deletes the credential at the key, or returns not found
func (c *Credentials) Delete(_ context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.values[key]; !ok {
		return goauth.ErrNotFound.With(key)
	}
	delete(c.values, key)
	return nil
}

// Expand returns the value, as it is
func (c *Credentials) Expand(_ context.Context, value string) (string, error) {
	return value, nil
}
