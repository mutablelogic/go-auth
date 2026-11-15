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

//go:build !client && !cert

package main

import (
	// Packages
	pg "github.com/mutablelogic/go-pg"
	server "github.com/mutablelogic/go-server"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// CertFlags has no flags, as the certificate manager isn't built in
type CertFlags struct{}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// withHandlers calls fn without the certificate handlers
func (CertFlags) withHandlers(_ server.Cmd, _ pg.PoolConn, _ *follow, _ []string, fn func(*module) error) error {
	return fn(nil)
}
