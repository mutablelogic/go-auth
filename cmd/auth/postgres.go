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
	// Packages
	pg "github.com/mutablelogic/go-pg"
	pgcmd "github.com/mutablelogic/go-pg/pkg/cmd"
	server "github.com/mutablelogic/go-server"
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
// pool, which is nil otherwise, and closes it afterwards
func (flags PostgresFlags) withPool(ctx server.Cmd, fn func(pg.PoolConn) error) error {
	pool, err := flags.PostgresFlags.Connect(ctx)
	if err != nil {
		return err
	} else if pool != nil {
		defer pool.Close()
	}
	return fn(pool)
}
