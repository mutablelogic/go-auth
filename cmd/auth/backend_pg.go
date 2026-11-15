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
	// Packages
	auth "github.com/mutablelogic/go-auth"
	credential "github.com/mutablelogic/go-auth/credential"
	credentialcmd "github.com/mutablelogic/go-auth/credential/cmd"
	pgcredential "github.com/mutablelogic/go-auth/credential/pg"
	pg "github.com/mutablelogic/go-pg"
	server "github.com/mutablelogic/go-server"
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

func (flags BackendFlags) withManager(ctx server.Cmd, pool pg.PoolConn, follow *follow, passphrases []string, fn func(credential.CredentialManager, bool) error) error {
	// The pool is the server's, which the certificate manager shares
	if pool == nil || follow == nil {
		return auth.ErrBadParameter.With("a PostgreSQL connection URL is required: set --pg.url")
	}

	// The credential table's trigger notifies the server's channel of its
	// changes, which the server follows
	return credentialcmd.WithPGCredentialManager(ctx, pool, flags.Schema, passphrases, func(manager credential.CredentialManager) error {
		return fn(manager, true)
	}, pgcredential.WithChannel(follow.channel))
}
