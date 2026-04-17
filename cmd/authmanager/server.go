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
	"fmt"

	// Packages
	authhandler "github.com/mutablelogic/go-auth/auth/httphandler"
	auth "github.com/mutablelogic/go-auth/auth/manager"
	cert "github.com/mutablelogic/go-auth/cert/manager"
	ldap "github.com/mutablelogic/go-auth/ldap/manager"
	pg "github.com/mutablelogic/go-pg"
	server "github.com/mutablelogic/go-server"
	cmd "github.com/mutablelogic/go-server/pkg/cmd"
	errgroup "golang.org/x/sync/errgroup"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type ServerCommands struct {
	Run AuthServer `cmd:"" name:"run" help:"Run the authentication server." group:"SERVER"`
}

type AuthServer struct {
	cmd.RunServer
	PostgresFlags       `embed:"" prefix:"pg."`
	LDAPFlags           `embed:"" prefix:"ldap."`
	CertFlags           `embed:"" prefix:"cert."`
	LocalProviderFlags  `embed:"" prefix:"local."`
	GoogleProviderFlags `embed:"" prefix:"google."`
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *AuthServer) Run(ctx server.Cmd) error {
	ctx.Logger().DebugContext(ctx.Context(), "Connecting to database", "name", ctx.Name(), "version", ctx.Version())
	pool, err := cmd.PostgresFlags.Connect(ctx)
	if err != nil {
		return err
	} else if pool == nil {
		return fmt.Errorf("No database connection URL provided")
	}
	defer pool.Close()

	// Create an auth manager in the inner context
	return cmd.WithAuthManager(ctx, pool, true, func(authmanager *auth.Manager) error {
		return cmd.WithCertManager(ctx, pool, func(certmanager *cert.Manager) error {
			return cmd.WithLDAPManager(ctx, pool, func(ldapmanager *ldap.Manager) error {
				errgroup, errctx := errgroup.WithContext(ctx.Context())

				// Run the auth manager
				if authmanager != nil {
					ctx.Logger().DebugContext(ctx.Context(), "Running the Auth manager")
					errgroup.Go(func() error {
						return authmanager.Run(errctx)
					})
				}

				// Run the ldap manager
				if ldapmanager != nil {
					ctx.Logger().DebugContext(ctx.Context(), "Running the LDAP manager")
					errgroup.Go(func() error {
						return ldapmanager.Run(errctx, ctx.Logger())
					})
				}

				// Run the http server
				errgroup.Go(func() error {
					return cmd.RunServer.Run(ctx)
				})

				// Run all the goroutines until one errors, and return any errors
				return errgroup.Wait()
			})
		})
	})
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - AUTH MANAGER

func (cmd *AuthServer) WithAuthManager(ctx server.Cmd, conn pg.PoolConn, enabled bool, fn func(manager *auth.Manager) error) error {
	// Skip if enabled is false
	if enabled == false {
		return fn(nil)
	}

	// Create the auth manager
	ctx.Logger().DebugContext(ctx.Context(), "Creating Auth manager")
	manager, err := auth.New(ctx.Context(), conn)
	if err != nil {
		return err
	}

	// Register the HTTP handler routes
	cmd.RunServer.Register(
		authhandler.RegisterAuthHandlers(manager),
	)

	// Next callback in the chain
	return fn(manager)
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - CERT MANAGER

func (cmd *AuthServer) WithCertManager(ctx server.Cmd, conn pg.PoolConn, fn func(manager *cert.Manager) error) error {
	opts := cmd.CertFlags.Options(ctx)
	if opts == nil {
		return fn(nil)
	}

	// Create the cert manager
	ctx.Logger().DebugContext(ctx.Context(), "Creating Certificate manager")
	manager, err := cert.New(ctx.Context(), conn, opts...)
	if err != nil {
		return err
	}

	// TODO: Register the HTTP handler routes

	// Next callback in the chain
	return fn(manager)
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - LDAP MANAGER

func (cmd *AuthServer) WithLDAPManager(ctx server.Cmd, conn pg.PoolConn, fn func(manager *ldap.Manager) error) error {
	opts := cmd.LDAPFlags.Options(ctx)
	if opts == nil {
		return fn(nil)
	}

	// Create the LDAP manager
	ctx.Logger().DebugContext(ctx.Context(), "Creating LDAP manager")
	manager, err := ldap.New(opts...)
	if err != nil {
		return err
	}

	// TODO: Register the HTTP handler routes

	// Next callback in the chain
	return fn(manager)
}
