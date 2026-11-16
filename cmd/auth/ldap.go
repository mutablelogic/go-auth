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

//go:build !client && ldap

package main

import (
	// Packages
	auth "github.com/mutablelogic/go-auth"
	ldapcmd "github.com/mutablelogic/go-auth/ldap/cmd"
	ldaphandler "github.com/mutablelogic/go-auth/ldap/httphandler"
	manager "github.com/mutablelogic/go-auth/ldap/manager"
	server "github.com/mutablelogic/go-server"
	broadcaster "github.com/mutablelogic/go-server/broadcaster"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// LDAPFlags configure the LDAP manager
type LDAPFlags struct {
	ldapcmd.ServerFlags
	Insecure bool `name:"insecure" env:"${ENV_NAME}_LDAP_INSECURE" help:"Serve the LDAP API, which has no authentication yet, so anyone who can reach the server can change the directory, as the manager's user"`
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// withHandlers creates the LDAP manager, which publishes its changes, and
// its connection coming up or going down, to the server's, and calls fn
// with the registration of its handlers, while it runs
func (flags LDAPFlags) withHandlers(ctx server.Cmd, changes *broadcaster.Broadcaster, fn func(*module) error) error {
	// Until the API has authentication, serving it is a choice, as it
	// changes the directory as the manager's user
	if !flags.Insecure {
		return auth.ErrBadParameter.With("the LDAP API has no authentication yet, so anyone who can reach the server could change the directory: set --ldap.insecure to serve it anyway")
	}
	return flags.WithLDAPManager(ctx, changes, func(mgr *manager.Manager) error {
		ctx.Logger().WarnContext(ctx.Context(), "The LDAP API has no authentication, as --ldap.insecure is set")
		return fn(&module{register: ldaphandler.RegisterHandlers(mgr, false)})
	})
}
