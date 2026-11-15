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
	pgbroadcaster "github.com/mutablelogic/go-pg/pgbroadcaster"
	pgbroadcasterschema "github.com/mutablelogic/go-pg/pgbroadcaster/schema"
	pgcmd "github.com/mutablelogic/go-pg/pkg/cmd"
	server "github.com/mutablelogic/go-server"
	broadcaster "github.com/mutablelogic/go-server/broadcaster"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// BackendFlags stores credentials in PostgreSQL
type BackendFlags struct {
	credentialcmd.PGFlags
	pgcmd.PostgresFlags
	Schema string `name:"schema" env:"PG_SCHEMA" help:"Database schema for the credential table"`
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	backend = "pg"
)

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func (flags BackendFlags) withManager(ctx server.Cmd, changes *broadcaster.Broadcaster, fn func(credential.CredentialManager, follow) error) error {
	// Connect to the database, with go-pg's flags
	pool, err := flags.PostgresFlags.Connect(ctx)
	if err != nil {
		return err
	} else if pool == nil {
		return auth.ErrBadParameter.With("a PostgreSQL connection URL is required: set --credential.url")
	}
	defer pool.Close()

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
	return flags.WithPGCredentialManager(ctx, pool, flags.Schema, func(manager credential.CredentialManager) error {
		return fn(manager, func(runctx context.Context) error {
			return listener.Run(runctx, ctx.Logger())
		})
	}, pgcredential.WithChannel(pgbroadcasterschema.NotifyChannel))
}
