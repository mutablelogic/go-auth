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

//go:build !client && (pg || cert)

package main

import (
	"context"

	// Packages
	pg "github.com/mutablelogic/go-pg"
	pgbroadcaster "github.com/mutablelogic/go-pg/pgbroadcaster"
	pgbroadcasterschema "github.com/mutablelogic/go-pg/pgbroadcaster/schema"
	pgcmd "github.com/mutablelogic/go-pg/pkg/cmd"
	server "github.com/mutablelogic/go-server"
	broadcaster "github.com/mutablelogic/go-server/broadcaster"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// PostgresFlags connect to PostgreSQL, which the pg credential backend and
// the certificate manager share
type PostgresFlags struct {
	pgcmd.PostgresFlags
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// withPool connects to PostgreSQL, when a URL is set, and calls fn with the
// pool, and a follower of the changes its tables' triggers notify the
// channel of, which pgbroadcaster publishes to the server's changes,
// whatever makes them, such as another server, or SQL. Without a URL, both
// are nil. The pool is closed afterwards.
func (flags PostgresFlags) withPool(ctx server.Cmd, changes *broadcaster.Broadcaster, fn func(pg.PoolConn, *follow) error) error {
	pool, err := flags.PostgresFlags.Connect(ctx)
	if err != nil {
		return err
	} else if pool == nil {
		return fn(nil, nil)
	}
	defer pool.Close()

	listener, err := pgbroadcaster.New(ctx.Context(), pool,
		pgbroadcaster.WithTracer(ctx.Tracer()),
		pgbroadcaster.WithChannel(pgbroadcasterschema.NotifyChannel),
		pgbroadcaster.WithBroadcaster(changes),
	)
	if err != nil {
		return err
	}
	return fn(pool, &follow{
		channel: pgbroadcasterschema.NotifyChannel,
		run: func(runctx context.Context) error {
			return listener.Run(runctx, ctx.Logger())
		},
		ready: listener.WaitListening,
	})
}
