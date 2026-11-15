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

package file

import (
	// Packages
	credential "github.com/mutablelogic/go-auth/credential"
	env "github.com/mutablelogic/go-auth/credential/env"
	crypto "github.com/mutablelogic/go-auth/crypto"
	trace "go.opentelemetry.io/otel/trace"
)

////////////////////////////////////////////////////////////////////////////////
// TYPES

// Opt is a functional option for the file credential manager
type Opt func(*opt) error

type opt struct {
	tracer      trace.Tracer
	passphrases *crypto.Passphrases
	env         credential.CredentialProvider
	useEnv      bool
}

////////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func (o *opt) apply(opts []Opt) error {
	o.passphrases = crypto.NewPassphrases()
	for _, fn := range opts {
		if err := fn(o); err != nil {
			return err
		}
	}

	// The environment provider uses the tracer, which can be set after
	// WithEnv
	if o.useEnv {
		o.env = env.New(env.WithTracer(o.tracer))
	}
	return nil
}

////////////////////////////////////////////////////////////////////////////////
// OPTIONS

// WithTracer sets the tracer used for tracing operations
func WithTracer(tracer trace.Tracer) Opt {
	return func(o *opt) error {
		o.tracer = tracer
		return nil
	}
}

// WithPassphrase registers a passphrase for a passphrase version. Credentials
// are encrypted with the latest version, and decrypted with the version they
// were encrypted with. Versions are uint64 and passphrases must be non-empty.
func WithPassphrase(version uint64, passphrase string) Opt {
	return func(o *opt) error {
		return o.passphrases.Set(version, passphrase)
	}
}

// WithEnv reads a credential from the environment when it isn't stored in a
// file, so $KEY is expanded from the environment variable KEY. The
// environment is read-only, so credentials are still stored in files.
func WithEnv() Opt {
	return func(o *opt) error {
		o.useEnv = true
		return nil
	}
}
