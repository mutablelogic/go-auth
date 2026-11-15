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
	pg "github.com/mutablelogic/go-pg"
	server "github.com/mutablelogic/go-server"
	logger "github.com/mutablelogic/go-server/pkg/logger"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// BackendFlags stores credentials in PostgreSQL
type BackendFlags struct {
	credentialcmd.PGFlags
	URL      string `name:"url" env:"PG_URL" help:"PostgreSQL connection URL"`
	Password string `name:"password" env:"PG_PASSWORD" help:"PostgreSQL password"`
	Schema   string `name:"schema" env:"CREDENTIAL_SCHEMA" help:"Database schema for the credential table"`
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	backend = "pg"
)

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func (flags BackendFlags) withManager(ctx server.Cmd, fn func(credential.CredentialManager) error) error {
	if flags.URL == "" {
		return auth.ErrBadParameter.With("a PostgreSQL connection URL is required: set --credential.url")
	}

	// Connect to the database
	opts := []pg.Opt{
		pg.WithURL(flags.URL),
		pg.WithTracer(ctx.Tracer()),
		pg.WithTrace(func(c context.Context, sql string, args any, err error) {
			if err != nil {
				ctx.Logger().Log(c, logger.LevelDebug, sql, "args", args, "err", err)
			} else {
				ctx.Logger().Log(c, logger.LevelTrace, sql, "args", args)
			}
		}),
	}
	if flags.Password != "" {
		opts = append(opts, pg.WithPassword(flags.Password))
	}
	pool, err := pg.NewPool(ctx.Context(), opts...)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := pool.Ping(ctx.Context()); err != nil {
		return err
	}

	return flags.WithPGCredentialManager(ctx, pool, flags.Schema, fn)
}
