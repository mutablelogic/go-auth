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

package bitwarden

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"slices"
	"strings"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	credential "github.com/mutablelogic/go-auth/credential"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	types "github.com/mutablelogic/go-server/pkg/types"
	attribute "go.opentelemetry.io/otel/attribute"
	trace "go.opentelemetry.io/otel/trace"
)

////////////////////////////////////////////////////////////////////////////////
// TYPES

// Manager stores credentials as secrets in Bitwarden Secrets Manager, one
// for each key, which are encrypted and decrypted here with the
// organization's key, as Bitwarden is end-to-end encrypted
type Manager struct {
	opt
	client *client
}

var _ credential.CredentialProvider = (*Manager)(nil)
var _ credential.CredentialManager = (*Manager)(nil)

////////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// New returns a manager for credentials in Bitwarden Secrets Manager, for a
// machine account's access token, from BWS_ACCESS_TOKEN or WithAccessToken.
// The server is Bitwarden's US cloud, unless it's set with BWS_SERVER_URL,
// WithServerURL or WithURLs. It logs in when it's first used.
func New(opts ...Opt) (_ *Manager, err error) {
	self := new(Manager)
	if err := self.opt.apply(opts); err != nil {
		return nil, err
	}

	// Trace creating the manager, which needs the tracer from the options
	_, endSpan := otel.StartSpan(self.tracer, context.Background(), "credential.bitwarden.New",
		attribute.String("api", self.apiURL),
		attribute.String("identity", self.identityURL),
	)
	defer func() { endSpan(err) }()

	// Parse the access token
	if self.accessToken == "" {
		return nil, auth.ErrBadParameter.With("access token is required, from BWS_ACCESS_TOKEN or WithAccessToken")
	}
	token, err := parseAccessToken(self.accessToken)
	if err != nil {
		return nil, err
	}
	self.accessToken = ""
	self.client = &client{http: self.http, apiURL: self.apiURL, identityURL: self.identityURL, token: token}

	// Return success
	return self, nil
}

////////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Expand replaces each $KEY or ${KEY} placeholder in the value with the
// credential for the key, which must be a string, or with the environment
// variable, with WithEnv, when there is no secret for it. Keys containing
// "-" must use the ${KEY} form. The secrets are listed once, and each is
// read once, however many times it's used. Returns an error, rather than a
// partly expanded value, if a placeholder is not a valid key, or its
// credential does not exist or is not a string.
func (self *Manager) Expand(ctx context.Context, value string) (_ string, err error) {
	// The value isn't recorded, as it may contain secrets, only the keys of
	// the credentials used
	ctx, endSpan := otel.StartSpan(self.tracer, ctx, "credential.bitwarden.Expand")
	defer func() { endSpan(err) }()

	var result error
	var index map[string][]string
	cache := make(map[string]string)
	defer func() {
		trace.SpanFromContext(ctx).SetAttributes(attribute.StringSlice("keys", slices.Sorted(maps.Keys(cache))))
	}()
	expanded := os.Expand(value, func(name string) string {
		if result != nil {
			return ""
		} else if value, exists := cache[name]; exists {
			return value
		}

		// List the secrets when the first placeholder is expanded
		if index == nil {
			if index, result = self.index(ctx); result != nil {
				return ""
			}
		}
		value, err := self.lookup(ctx, name, index)
		if err != nil {
			result = err
			return ""
		}
		cache[name] = value
		return value
	})
	if result != nil {
		return "", result
	}
	return expanded, nil
}

// Get returns the credential for the key, as JSON, or the environment
// variable's value, with WithEnv, when there is no secret for it. A secret
// which isn't JSON is returned as a JSON string. Returns an error if the key
// isn't valid, or the credential doesn't exist.
func (self *Manager) Get(ctx context.Context, key string) (_ json.RawMessage, err error) {
	ctx, endSpan := otel.StartSpan(self.tracer, ctx, "credential.bitwarden.Get",
		attribute.String("key", key),
	)
	defer func() { endSpan(err) }()

	if err := validateKey(key); err != nil {
		return nil, err
	}
	index, err := self.index(ctx)
	if err != nil {
		return nil, err
	}
	value, err := self.read(ctx, key, index)
	if errors.Is(err, auth.ErrNotFound) && self.env != nil {
		return self.env.Get(ctx, key)
	} else if err != nil {
		return nil, err
	}
	if json.Valid([]byte(value)) {
		return json.RawMessage(value), nil
	}
	return json.Marshal(value)
}

// Set stores the credential for the key, replacing the value of its secret,
// or creating the secret in the projects set with WithProject when there
// isn't one. A JSON string is stored without its quotes, so it reads as
// plain text in Bitwarden and with bws, and other JSON is stored as it is.
// Returns an error if the key isn't valid, the value isn't JSON, or there
// is more than one secret with the key.
func (self *Manager) Set(ctx context.Context, key string, value json.RawMessage) (err error) {
	ctx, endSpan := otel.StartSpan(self.tracer, ctx, "credential.bitwarden.Set",
		attribute.String("key", key),
	)
	defer func() { endSpan(err) }()

	if err := validateKey(key); err != nil {
		return err
	} else if !json.Valid(value) {
		return auth.ErrBadParameter.Withf("credential %q is not JSON", key)
	}
	text := string(value)
	var str string
	if err := json.Unmarshal(value, &str); err == nil {
		text = str
	}

	// Update the secret, keeping its note and projects, or create it
	index, err := self.index(ctx)
	if err != nil {
		return err
	}
	id, err := find(key, index)
	if errors.Is(err, auth.ErrNotFound) {
		return writeErr(key, self.client.createSecret(ctx, secret{Key: key, Value: text, ProjectIDs: self.projectIDs}))
	} else if err != nil {
		return err
	}
	existing, err := self.client.getSecret(ctx, id)
	if err != nil {
		return err
	}
	existing.Value = text
	return writeErr(key, self.client.updateSecret(ctx, *existing))
}

// List returns the stored credentials, in key order, without their values:
// the secrets the machine account can read, whose keys are valid. A key
// which is on more than one secret is listed for each of them.
func (self *Manager) List(ctx context.Context) (_ []credential.Credential, err error) {
	ctx, endSpan := otel.StartSpan(self.tracer, ctx, "credential.bitwarden.List")
	defer func() { endSpan(err) }()

	secrets, err := self.client.listSecrets(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]credential.Credential, 0, len(secrets))
	for _, s := range secrets {
		if validateKey(s.Key) == nil {
			result = append(result, credential.Credential{Key: s.Key, UpdatedAt: s.Revised})
		}
	}
	slices.SortStableFunc(result, func(a, b credential.Credential) int {
		return strings.Compare(a.Key, b.Key)
	})
	return result, nil
}

// Delete deletes the key's secret, and returns ErrNotFound when there isn't
// one, or ErrConflict when there is more than one, rather than delete them
// all
func (self *Manager) Delete(ctx context.Context, key string) (err error) {
	ctx, endSpan := otel.StartSpan(self.tracer, ctx, "credential.bitwarden.Delete",
		attribute.String("key", key),
	)
	defer func() { endSpan(err) }()

	if err := validateKey(key); err != nil {
		return err
	}
	index, err := self.index(ctx)
	if err != nil {
		return err
	}
	id, err := find(key, index)
	if err != nil {
		return err
	}
	return writeErr(key, self.client.deleteSecret(ctx, id))
}

////////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// index returns the identifiers of the secrets for each key
func (self *Manager) index(ctx context.Context) (map[string][]string, error) {
	secrets, err := self.client.listSecrets(ctx)
	if err != nil {
		return nil, err
	}
	index := make(map[string][]string, len(secrets))
	for _, s := range secrets {
		index[s.Key] = append(index[s.Key], s.ID)
	}
	return index, nil
}

// lookup returns the credential for the placeholder name, which must be a
// string. An environment variable is used as it is, as it's a string even
// when it looks like JSON, such as a number.
func (self *Manager) lookup(ctx context.Context, name string, index map[string][]string) (string, error) {
	if err := validateKey(name); err != nil {
		return "", auth.ErrBadParameter.Withf("invalid credential placeholder %q", name)
	}
	value, err := self.read(ctx, name, index)
	if errors.Is(err, auth.ErrNotFound) && self.env != nil {
		return self.env.Expand(ctx, "${"+name+"}")
	} else if err != nil {
		return "", err
	}

	// A secret which is a JSON string is used without its quotes, other JSON
	// isn't a string, and anything else is used as it is
	if !json.Valid([]byte(value)) {
		return value, nil
	}
	var result string
	if err := json.Unmarshal([]byte(value), &result); err != nil {
		return "", auth.ErrBadParameter.Withf("credential %q is not a string", name)
	}
	return result, nil
}

// read returns the value of the key's secret
func (self *Manager) read(ctx context.Context, key string, index map[string][]string) (string, error) {
	id, err := find(key, index)
	if err != nil {
		return "", err
	}
	s, err := self.client.getSecret(ctx, id)
	if err != nil {
		return "", err
	}
	return s.Value, nil
}

// find returns the identifier of the key's secret, or an error when there
// isn't one, or there's more than one, as Bitwarden doesn't require keys to
// be unique
func find(key string, index map[string][]string) (string, error) {
	switch ids := index[key]; len(ids) {
	case 0:
		return "", auth.ErrNotFound.Withf("credential %q not found", key)
	case 1:
		return ids[0], nil
	default:
		return "", auth.ErrConflict.Withf("credential %q: there are %d secrets with the key", key, len(ids))
	}
}

// writeErr returns ErrForbidden for ErrNotFound, as Bitwarden returns 404,
// rather than 403, when the machine account can't write to the project or
// the secret
func writeErr(key string, err error) error {
	if errors.Is(err, auth.ErrNotFound) {
		return auth.ErrForbidden.Withf("credential %q: the machine account needs write access to the project: %w", key, err)
	}
	return err
}

// validateKey returns an error if the key isn't an identifier
func validateKey(key string) error {
	if !types.IsIdentifier(key) {
		return auth.ErrBadParameter.Withf("credential key %q must be an identifier", key)
	}
	return nil
}
