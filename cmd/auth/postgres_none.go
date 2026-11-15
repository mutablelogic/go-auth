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

//go:build !client && !pg && !cert

package main

import (
	// Packages
	pg "github.com/mutablelogic/go-pg"
	server "github.com/mutablelogic/go-server"
	broadcaster "github.com/mutablelogic/go-server/broadcaster"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// PostgresFlags has no flags, as nothing which is built in uses PostgreSQL
type PostgresFlags struct{}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// withPool calls fn without a pool, or a follower of its changes
func (PostgresFlags) withPool(_ server.Cmd, _ *broadcaster.Broadcaster, fn func(pg.PoolConn, *follow) error) error {
	return fn(nil, nil)
}
