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

//go:build !client

package main

import (
	"context"
	"errors"

	// Packages
	httphandler "github.com/djthorpe/go-auth/pkg/httphandler/ldap"
	ldap "github.com/djthorpe/go-auth/pkg/ldapmanager"
	server "github.com/mutablelogic/go-server"
	cmd "github.com/mutablelogic/go-server/pkg/cmd"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	errgroup "golang.org/x/sync/errgroup"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type ServerCommands struct {
	RunServer RunServer `cmd:"" name:"run" help:"Run server." group:"SERVER"`
}

type RunServer struct {
	cmd.RunServer
	LDAPFlags `embed:"" prefix:"ldap."`
}

type LDAPFlags struct {
	Url    string `long:"url" description:"LDAP URL to listen on" default:"ldap://localhost:389" env:"LDAP_URL"`
	User   string `long:"user" description:"Bind user DN for LDAP manager" default:"cn=admin,dc=example,dc=org" env:"LDAP_USER"`
	Pass   string `long:"pass" description:"Bind password for LDAP manager" env:"LDAP_PASS"`
	BaseDN string `long:"base-dn" description:"Base DN for LDAP entries" default:"dc=example,dc=org" env:"LDAP_BASEDN"`
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (server *RunServer) Run(ctx server.Cmd) error {
	return server.WithManager(ctx, func(manager *ldap.Manager, v string) error {
		ctx.Logger().Info("starting LDAP manager server", "version", v)

		// Register HTTP handlers
		server.RunServer.Register(func(router *httprouter.Router) error {
			var result error
			result = errors.Join(result, httphandler.RegisterHandlers(manager, router, true))
			return result
		})

		// Create a cancelable context and errgroup to run the manager and server concurrently
		// and cancel both of them if either returns an error or when the parent context is done
		parent, cancel := context.WithCancel(ctx.Context())
		group, groupCtx := errgroup.WithContext(parent)

		// Run the manager and server in separate goroutines, and cancel both if either returns an error
		group.Go(func() error {
			defer cancel()
			return manager.Run(groupCtx, ctx.Logger())
		})
		group.Go(func() error {
			defer cancel()
			return server.RunServer.Run(ctx)
		})

		// Return the first error from either goroutine, or nil if both complete successfully
		return group.Wait()
	})
}

// WithManager creates the resource manager, registers all resource instances
// (logger, otel, handlers, router) in dependency order, invokes fn, then
// closes the manager regardless of whether fn returned an error.
func (server *RunServer) WithManager(ctx server.Cmd, fn func(*ldap.Manager, string) error) error {
	opts := []ldap.Opt{
		ldap.WithUrl(server.Url),
		ldap.WithUser(server.User),
		ldap.WithPassword(server.Pass),
		ldap.WithBaseDN(server.BaseDN),
	}

	// Create the manager with the options required
	manager, err := ldap.New(opts...)
	if err != nil {
		return err
	}

	// Invoke the function with the manager and version string
	return fn(manager, ctx.Version())
}
