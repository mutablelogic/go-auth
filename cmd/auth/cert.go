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

//go:build !client && cert

package main

import (
	// Packages
	auth "github.com/mutablelogic/go-auth"
	certcmd "github.com/mutablelogic/go-auth/cert/cmd"
	certhandler "github.com/mutablelogic/go-auth/cert/httphandler"
	manager "github.com/mutablelogic/go-auth/cert/manager"
	pg "github.com/mutablelogic/go-pg"
	server "github.com/mutablelogic/go-server"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// CertFlags configure the certificate manager, which needs PostgreSQL
type CertFlags struct {
	certcmd.ServerFlags
	Schema string `name:"schema" env:"${ENV_NAME}_CERT_SCHEMA" help:"Database schema for the certificate tables, which is cert when it's not set"`
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// withHandlers creates the certificate manager, in the pool, with the
// passphrases, and calls fn with the registration of its handlers
func (flags CertFlags) withHandlers(ctx server.Cmd, pool pg.PoolConn, passphrases []string, fn func(registerFunc) error) error {
	if pool == nil {
		return auth.ErrBadParameter.With("certificates need a PostgreSQL connection: set --pg.url")
	}
	return flags.WithCertManager(ctx, pool, flags.Schema, passphrases, func(mgr *manager.Manager) error {
		ctx.Logger().InfoContext(ctx.Context(), "Certificates", "root", flags.Root != "")
		ctx.Logger().WarnContext(ctx.Context(), "The certificate API has no authentication")
		return fn(certhandler.RegisterHandlers(mgr, false))
	})
}
