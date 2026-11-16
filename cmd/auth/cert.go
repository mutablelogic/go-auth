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
	cert "github.com/mutablelogic/go-auth/cert/cert"
	certcmd "github.com/mutablelogic/go-auth/cert/cmd"
	certhandler "github.com/mutablelogic/go-auth/cert/httphandler"
	manager "github.com/mutablelogic/go-auth/cert/manager"
	pg "github.com/mutablelogic/go-pg"
	server "github.com/mutablelogic/go-server"
	config "github.com/mutablelogic/go-server/config"
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
// passphrases, whose triggers notify the server's channel of its changes,
// and calls fn with the registration of its handlers, when insecure is set
func (flags CertFlags) withHandlers(ctx server.Cmd, pool pg.PoolConn, follow *follow, passphrases []string, insecure bool, fn func(*module) error) error {
	if pool == nil || follow == nil {
		return auth.ErrBadParameter.With("certificates need a PostgreSQL connection: set --pg.url")
	}

	// Until the API has authentication, serving it is a choice, as it
	// issues certificates under the root, and returns their private keys
	if !insecure {
		return auth.ErrBadParameter.With("the certificate API has no authentication yet, so anyone who can reach the server could create certificates and get their private keys: set --insecure to serve it anyway")
	}
	return flags.WithCertManager(ctx, pool, flags.Schema, passphrases, func(mgr *manager.Manager) error {
		if flags.Root != "" {
			ctx.Logger().InfoContext(ctx.Context(), "Certificates", "root", flags.Root)
		} else {
			ctx.Logger().InfoContext(ctx.Context(), "Certificates", "root", "generated")
		}
		ctx.Logger().WarnContext(ctx.Context(), "The certificate API has no authentication, as --insecure is set")
		// The web UI includes certificates when the configuration has
		// their section, which says whether there's a root
		root, err := mgr.HasRoot(ctx.Context())
		if err != nil {
			return err
		}
		return fn(&module{
			register: certhandler.RegisterHandlers(mgr, false),
			section:  config.WithSection("cert", cert.Features{Root: root}),
		})
	}, manager.WithChannel(follow.channel))
}
