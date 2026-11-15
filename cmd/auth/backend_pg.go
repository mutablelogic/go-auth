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

//go:build !client && pg

package main

import (
	"context"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	credential "github.com/mutablelogic/go-auth/credential"
	credentialcmd "github.com/mutablelogic/go-auth/credential/cmd"
	pgcredential "github.com/mutablelogic/go-auth/credential/pg"
	pg "github.com/mutablelogic/go-pg"
	pgbroadcaster "github.com/mutablelogic/go-pg/pgbroadcaster"
	pgbroadcasterschema "github.com/mutablelogic/go-pg/pgbroadcaster/schema"
	server "github.com/mutablelogic/go-server"
	broadcaster "github.com/mutablelogic/go-server/broadcaster"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// BackendFlags stores credentials in PostgreSQL
type BackendFlags struct {
	Schema string `name:"schema" env:"PG_SCHEMA" help:"Database schema for the credential table"`
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	backend = "pg"
)

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func (flags BackendFlags) withManager(ctx server.Cmd, pool pg.PoolConn, passphrases []string, changes *broadcaster.Broadcaster, fn func(credential.CredentialManager, *follow) error) error {
	// The pool is the server's, which the certificate manager shares
	if pool == nil {
		return auth.ErrBadParameter.With("a PostgreSQL connection URL is required: set --pg.url")
	}

	// The credential table's trigger notifies pgbroadcaster's channel of its
	// changes, which pgbroadcaster publishes to the server's changes, whatever
	// makes them, such as another server, or SQL
	listener, err := pgbroadcaster.New(ctx.Context(), pool,
		pgbroadcaster.WithTracer(ctx.Tracer()),
		pgbroadcaster.WithChannel(pgbroadcasterschema.NotifyChannel),
		pgbroadcaster.WithBroadcaster(changes),
	)
	if err != nil {
		return err
	}
	return credentialcmd.WithPGCredentialManager(ctx, pool, flags.Schema, passphrases, func(manager credential.CredentialManager) error {
		return fn(manager, &follow{
			run: func(runctx context.Context) error {
				return listener.Run(runctx, ctx.Logger())
			},
			ready: listener.WaitListening,
		})
	}, pgcredential.WithChannel(pgbroadcasterschema.NotifyChannel))
}
