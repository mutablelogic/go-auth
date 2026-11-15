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

package pg

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"slices"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	credential "github.com/mutablelogic/go-auth/credential"
	schema "github.com/mutablelogic/go-auth/credential/pg/schema"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	pg "github.com/mutablelogic/go-pg"
	attribute "go.opentelemetry.io/otel/attribute"
	trace "go.opentelemetry.io/otel/trace"
)

////////////////////////////////////////////////////////////////////////////////
// TYPES

// provider expands credential placeholders using the manager's credentials,
// and then the environment's, when WithEnv is set
type provider struct {
	manager *Manager
	env     credential.CredentialProvider
}

// nullProvider is used when there are no credentials, and fails to expand any
// placeholder
type nullProvider struct{}

var _ credential.CredentialProvider = (*provider)(nil)
var _ credential.CredentialManager = (*provider)(nil)
var _ credential.CredentialRotator = (*provider)(nil)
var _ credential.CredentialDecrypter = (*provider)(nil)
var _ credential.CredentialProvider = nullProvider{}

////////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// GetCredentialProvider returns a provider which substitutes credentials for
// placeholders. Credentials are decrypted without a passphrase, so the
// provider is for internal server-side use only, and must not be exposed via
// any public API or HTTP handler. With WithEnv, a credential which isn't
// stored is read from the environment, and without a passphrase, every
// credential is.
func (self *Manager) GetCredentialProvider() credential.CredentialProvider {
	if len(self.passphrases.Keys()) == 0 {
		if self.env != nil {
			return self.env
		}
		return NullProvider()
	}
	return &provider{manager: self, env: self.env}
}

// NullProvider returns a provider for when there are no credentials, such as
// when no passphrase is configured. A value without placeholders is returned
// unchanged, and a value with placeholders is an error.
func NullProvider() credential.CredentialProvider {
	return nullProvider{}
}

// Expand replaces each $KEY or ${KEY} placeholder in the value with the
// credential for the key, which must be a string. Keys containing "-" must use
// the ${KEY} form. Each credential is read once, however many times it is
// used. Returns an error, rather than a partly expanded value, if a
// placeholder is not a valid key, or its credential does not exist or is not
// a string. As with os.Expand, the invalid syntax "${}" is removed.
func (self *provider) Expand(ctx context.Context, value string) (_ string, err error) {
	// The value isn't recorded, as it may contain secrets, only the keys of
	// the credentials used
	ctx, endSpan := otel.StartSpan(self.manager.tracer, ctx, "credential.pg.Expand")
	defer func() { endSpan(err) }()

	var result error
	cache := make(map[string]string)
	defer func() {
		trace.SpanFromContext(ctx).SetAttributes(attribute.StringSlice("keys", slices.Sorted(maps.Keys(cache))))
	}()
	expanded := os.Expand(value, func(name string) string {
		if result != nil {
			return ""
		} else if value, exists := cache[name]; exists {
			return value
		} else if value, err := self.lookup(ctx, name); err != nil {
			result = err
			return ""
		} else {
			cache[name] = value
			return value
		}
	})
	if result != nil {
		return "", result
	}
	return expanded, nil
}

// Get returns the credential for the key, as JSON, or the environment
// variable's value, with WithEnv, when it isn't stored. Returns an error if
// the key isn't valid, or the credential doesn't exist.
func (self *provider) Get(ctx context.Context, key string) (_ json.RawMessage, err error) {
	ctx, endSpan := otel.StartSpan(self.manager.tracer, ctx, "credential.pg.Get",
		attribute.String("key", key),
	)
	defer func() { endSpan(err) }()

	credentialKey := schema.CredentialKey{Key: key}
	if err := credentialKey.Validate(); err != nil {
		return nil, err
	}
	data, err := self.manager.GetCredentialWithoutPassphrase(ctx, credentialKey)
	if errors.Is(err, pg.ErrNotFound) {
		if self.env != nil {
			return self.env.Get(ctx, key)
		}
		return nil, auth.ErrNotFound.Withf("credential %q not found", key)
	} else if err != nil {
		return nil, err
	}
	return data, nil
}

// Set stores the credential for the key, encrypted with the latest
// passphrase, replacing any credential with the key. Returns an error if the
// key isn't valid, or the value isn't JSON.
func (self *provider) Set(ctx context.Context, key string, value json.RawMessage) (err error) {
	ctx, endSpan := otel.StartSpan(self.manager.tracer, ctx, "credential.pg.Set",
		attribute.String("key", key),
	)
	defer func() { endSpan(err) }()

	if !json.Valid(value) {
		return auth.ErrBadParameter.Withf("credential %q is not JSON", key)
	}
	_, err = self.manager.CreateCredential(ctx, schema.CredentialCreate{
		CredentialKey: schema.CredentialKey{Key: key},
		Credentials:   value,
	})
	return err
}

// List returns the stored credentials, in key order, without their values,
// reading them a page at a time
func (self *provider) List(ctx context.Context) (_ []credential.Credential, err error) {
	ctx, endSpan := otel.StartSpan(self.manager.tracer, ctx, "credential.pg.List")
	defer func() { endSpan(err) }()

	var result []credential.Credential
	for {
		limit := uint64(schema.CredentialListLimit)
		page, err := self.manager.ListCredentials(ctx, schema.CredentialListRequest{
			OffsetLimit: pg.OffsetLimit{Offset: uint64(len(result)), Limit: &limit},
		})
		if err != nil {
			return nil, err
		}
		for _, c := range page.Body {
			result = append(result, credential.Credential{Key: c.Key, Description: c.Description, UpdatedAt: c.UpdatedAt})
		}
		if len(page.Body) == 0 || uint64(len(result)) >= page.Count {
			return result, nil
		}
	}
}

// Delete removes the stored credential for the key, and returns ErrNotFound
// when there isn't one
func (self *provider) Delete(ctx context.Context, key string) (err error) {
	ctx, endSpan := otel.StartSpan(self.manager.tracer, ctx, "credential.pg.Delete",
		attribute.String("key", key),
	)
	defer func() { endSpan(err) }()

	_, err = self.manager.DeleteCredential(ctx, schema.CredentialKey{Key: key})
	return err
}

// Describe sets the description of the stored credential for the key, or
// removes it, when it's empty, and returns ErrNotFound when there isn't one
func (self *provider) Describe(ctx context.Context, key, description string) (err error) {
	ctx, endSpan := otel.StartSpan(self.manager.tracer, ctx, "credential.pg.Describe",
		attribute.String("key", key),
	)
	defer func() { endSpan(err) }()

	_, err = self.manager.DescribeCredential(ctx, schema.CredentialKey{Key: key}, description)
	return err
}

// Decrypt returns the credential for the key, as JSON, when the passphrase
// is the one it was encrypted with, or ErrForbidden when it isn't
func (self *provider) Decrypt(ctx context.Context, key, passphrase string) (_ json.RawMessage, err error) {
	ctx, endSpan := otel.StartSpan(self.manager.tracer, ctx, "credential.pg.Decrypt",
		attribute.String("key", key),
	)
	defer func() { endSpan(err) }()

	return self.manager.GetCredential(ctx, schema.CredentialKey{Key: key}, passphrase)
}

// Rotate re-encrypts the credential for the key with the latest passphrase,
// and returns ErrNotModified when it already uses it, or ErrNotFound when
// there isn't one
func (self *provider) Rotate(ctx context.Context, key string) (err error) {
	ctx, endSpan := otel.StartSpan(self.manager.tracer, ctx, "credential.pg.Rotate",
		attribute.String("key", key),
	)
	defer func() { endSpan(err) }()

	_, err = self.manager.RotateCredential(ctx, schema.CredentialKey{Key: key})
	return err
}

////////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// lookup returns the credential for the placeholder name, which must be a
// string
func (self *provider) lookup(ctx context.Context, name string) (string, error) {
	if err := (schema.CredentialKey{Key: name}).Validate(); err != nil {
		return "", auth.ErrBadParameter.Withf("invalid credential placeholder %q", name)
	}
	data, err := self.manager.GetCredentialWithoutPassphrase(ctx, schema.CredentialKey{Key: name})
	if errors.Is(err, pg.ErrNotFound) {
		// An environment variable is a string, even when it looks like JSON,
		// such as a number
		if self.env != nil {
			return self.env.Expand(ctx, "${"+name+"}")
		}
		return "", auth.ErrNotFound.Withf("credential %q not found", name)
	} else if err != nil {
		return "", err
	}
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return "", auth.ErrBadParameter.Withf("credential %q is not a string", name)
	}
	return value, nil
}

// errNoPassphrase is the error of the null provider, which has no
// credentials, as no passphrase is configured
func errNoPassphrase(key string) error {
	return auth.ErrServiceUnavailable.Withf("cannot use credential %q: no encryption passphrase configured for credentials", key)
}

// Get returns an error, as there are no credentials
func (nullProvider) Get(_ context.Context, key string) (json.RawMessage, error) {
	return nil, errNoPassphrase(key)
}

// Set returns an error, as credentials can't be stored
func (nullProvider) Set(_ context.Context, key string, _ json.RawMessage) error {
	return errNoPassphrase(key)
}

// Expand returns the value unchanged if it has no placeholders, or an error
// if it has any
func (nullProvider) Expand(_ context.Context, value string) (string, error) {
	var result error
	expanded := os.Expand(value, func(name string) string {
		if result == nil {
			result = auth.ErrServiceUnavailable.Withf("cannot expand credential %q: no encryption passphrase configured for credentials", name)
		}
		return ""
	})
	if result != nil {
		return "", result
	}
	return expanded, nil
}
