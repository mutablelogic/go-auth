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
	// Packages
	credential "github.com/mutablelogic/go-auth/credential"
	env "github.com/mutablelogic/go-auth/credential/env"
	schema "github.com/mutablelogic/go-auth/credential/pg/schema"
	crypto "github.com/mutablelogic/go-auth/crypto"
	trace "go.opentelemetry.io/otel/trace"
)

////////////////////////////////////////////////////////////////////////////////
// TYPES

// Opt is a functional option for credential manager configuration.
type Opt func(*opt) error

type opt struct {
	tracer      trace.Tracer
	schema      string
	passphrases *crypto.Passphrases
	env         credential.CredentialProvider
	useEnv      bool
}

////////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func (o *opt) apply(opt []Opt) error {
	o.defaults()

	// Apply options
	for _, fn := range opt {
		if err := fn(o); err != nil {
			return err
		}
	}

	// The environment provider uses the tracer, which can be set after
	// WithEnv
	if o.useEnv {
		o.env = env.New(env.WithTracer(o.tracer))
	}

	// Return success
	return nil
}

func (o *opt) defaults() {
	o.tracer = nil
	o.schema = schema.DefaultSchema
	o.passphrases = crypto.NewPassphrases()
	o.env = nil
	o.useEnv = false
}

////////////////////////////////////////////////////////////////////////////////
// OPTIONS

// WithTracer sets the tracer used for tracing operations.
func WithTracer(tracer trace.Tracer) Opt {
	return func(o *opt) error {
		o.tracer = tracer
		return nil
	}
}

// WithPassphrase registers an in-memory storage passphrase for a certificate
// passphrase version. Versions are uint64 and passphrases must be non-empty.
func WithPassphrase(version uint64, passphrase string) Opt {
	return func(o *opt) error {
		return o.passphrases.Set(version, passphrase)
	}
}

// WithSchema sets the database schema used for storing credentials.
func WithSchema(schema string) Opt {
	return func(o *opt) error {
		o.schema = schema
		return nil
	}
}

// WithEnv reads a credential from the environment when it isn't stored in
// the database, so $KEY is expanded from the environment variable KEY. The
// environment is read-only, so credentials are still stored in the database.
func WithEnv() Opt {
	return func(o *opt) error {
		o.useEnv = true
		return nil
	}
}
