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

//go:build !client && !ldap

package main

import (
	// Packages
	server "github.com/mutablelogic/go-server"
	broadcaster "github.com/mutablelogic/go-server/broadcaster"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// LDAPFlags has no flags, as the LDAP manager isn't built in
type LDAPFlags struct{}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// withHandlers calls fn without the LDAP handlers
func (LDAPFlags) withHandlers(_ server.Cmd, _ *broadcaster.Broadcaster, fn func(*module) error) error {
	return fn(nil)
}
