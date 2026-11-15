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

//go:build !client

package cert

import (
	"os"
	"strings"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	manager "github.com/mutablelogic/go-auth/cert/manager"
	pg "github.com/mutablelogic/go-pg"
	server "github.com/mutablelogic/go-server"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// ServerFlags configures the certificate manager, in a pool, schema and
// with passphrases, which are passed to WithCertManager
type ServerFlags struct {
	Root string `name:"root" env:"${ENV_NAME}_CERT_ROOT" type:"path" help:"PEM file with the root certificate and its RSA private key, which is imported when it isn't stored. A different root is an error."`
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// WithCertManager creates the certificate manager in the pool and schema,
// which is the default when it's empty, with the passphrases, for versions
// 1, 2 and so on, which encrypt its private keys, and the root, when it's
// set, and calls fn with it, with the manager's own options
func (flags ServerFlags) WithCertManager(ctx server.Cmd, pool pg.PoolConn, schema string, passphrases []string, fn func(*manager.Manager) error, opts ...manager.Opt) error {
	if pool == nil {
		return auth.ErrBadParameter.With("certificates need a PostgreSQL connection")
	}

	// The options, with the root, when it's set, which is read from its file
	base := []manager.Opt{manager.WithTracer(ctx.Tracer())}
	if schema := strings.TrimSpace(schema); schema != "" {
		base = append(base, manager.WithSchema(schema))
	}
	for i, passphrase := range passphrases {
		base = append(base, manager.WithPassphrase(uint64(i+1), passphrase))
	}
	if flags.Root != "" {
		data, err := os.ReadFile(flags.Root)
		if err != nil {
			return err
		}
		base = append(base, manager.WithRoot(string(data)))
	}

	mgr, err := manager.New(ctx.Context(), pool, append(base, opts...)...)
	if err != nil {
		return err
	}
	return fn(mgr)
}
