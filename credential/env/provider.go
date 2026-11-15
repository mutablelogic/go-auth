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

package env

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
	otel "github.com/mutablelogic/go-client/pkg/otel"
	attribute "go.opentelemetry.io/otel/attribute"
	trace "go.opentelemetry.io/otel/trace"
)

////////////////////////////////////////////////////////////////////////////////
// TYPES

// provider reads credentials from the process environment, which it can't
// change
type provider struct {
	tracer trace.Tracer
}

// Opt is a functional option for the environment provider
type Opt func(*provider)

var _ credential.CredentialProvider = (*provider)(nil)

////////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// New returns a provider which reads credentials from the environment
func New(opts ...Opt) credential.CredentialProvider {
	self := new(provider)
	for _, opt := range opts {
		opt(self)
	}
	return self
}

////////////////////////////////////////////////////////////////////////////////
// OPTIONS

// WithTracer sets the tracer used for tracing operations
func WithTracer(tracer trace.Tracer) Opt {
	return func(p *provider) {
		p.tracer = tracer
	}
}

////////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Expand expands the given value using the credential provider, substituting any
// credentials $PLACEHOLDER or ${PLACEHOLDER} as needed. It returns ErrNotFound,
// naming every placeholder which isn't set.
func (self *provider) Expand(ctx context.Context, value string) (_ string, err error) {
	// The value isn't recorded, as it may contain secrets, only the keys of
	// the variables used
	ctx, endSpan := otel.StartSpan(self.tracer, ctx, "credential.env.Expand")
	defer func() { endSpan(err) }()

	var missing []string
	used := make(map[string]struct{})
	defer func() {
		trace.SpanFromContext(ctx).SetAttributes(attribute.StringSlice("keys", slices.Sorted(maps.Keys(used))))
	}()
	result := os.Expand(value, func(key string) string {
		used[key] = struct{}{}
		value, ok := os.LookupEnv(key)
		if !ok && !slices.Contains(missing, key) {
			missing = append(missing, key)
		}
		return value
	})
	if len(missing) > 0 {
		errs := make([]error, 0, len(missing))
		for _, key := range missing {
			errs = append(errs, auth.ErrNotFound.Withf("credential %q", key))
		}
		return "", errors.Join(errs...)
	}
	return result, nil
}

// Get returns the credential for the key, as JSON. A value which isn't valid
// JSON is returned as a JSON string.
func (self *provider) Get(ctx context.Context, key string) (_ json.RawMessage, err error) {
	_, endSpan := otel.StartSpan(self.tracer, ctx, "credential.env.Get",
		attribute.String("key", key),
	)
	defer func() { endSpan(err) }()

	if key == "" {
		return nil, auth.ErrBadParameter.With("key is empty")
	}
	value, ok := os.LookupEnv(key)
	if !ok {
		return nil, auth.ErrNotFound.Withf("credential %q", key)
	}
	if json.Valid([]byte(value)) {
		return json.RawMessage(value), nil
	}
	return json.Marshal(value)
}

// Set returns ErrNotImplemented, since the environment can't be changed
func (self *provider) Set(ctx context.Context, key string, value json.RawMessage) (err error) {
	_, endSpan := otel.StartSpan(self.tracer, ctx, "credential.env.Set",
		attribute.String("key", key),
	)
	defer func() { endSpan(err) }()

	return auth.ErrNotImplemented.Withf("credential %q: the environment is read-only", key)
}
