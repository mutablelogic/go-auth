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

	// Packages
	credential "github.com/mutablelogic/go-auth/credential"
	httphandler "github.com/mutablelogic/go-auth/credential/httphandler"
	frontend "github.com/mutablelogic/go-auth/frontend/cmd"
	server "github.com/mutablelogic/go-server"
	broadcaster "github.com/mutablelogic/go-server/broadcaster"
	broadcastercmd "github.com/mutablelogic/go-server/broadcaster/cmd"
	config "github.com/mutablelogic/go-server/config"
	cmd "github.com/mutablelogic/go-server/pkg/cmd"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	errgroup "golang.org/x/sync/errgroup"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// ServerCommands run the credential server, with the backend which the
// build tags select: file (the default), pg, aws or bitwarden
type ServerCommands struct {
	Run RunServer `cmd:"" name:"run" help:"Run the credential server." group:"SERVER"`
	cmd.OpenAPICommands
}

// follow follows the backend's changes, such as pg's notifications, and
// publishes them, when the backend has its own changes, rather than the
// API's: run follows them, until the context is cancelled, and ready waits
// until it does, so the server doesn't accept a change before it would be
// published
type follow struct {
	run   func(context.Context) error
	ready func(context.Context) error
}

// without calls fn with a manager, without a follower of its changes, which
// the API publishes
func without(fn func(credential.CredentialManager, *follow) error) func(credential.CredentialManager) error {
	return func(manager credential.CredentialManager) error {
		return fn(manager, nil)
	}
}

// RunServer runs the credential server, with its web UI, when it's built
// in, and the changes, which the UI follows the server with
type RunServer struct {
	cmd.RunServer
	Credential  BackendFlags         `embed:"" prefix:"credential."`
	Broadcaster broadcastercmd.Flags `embed:"" prefix:"broadcaster."`
	Frontend    frontend.Flags       `embed:""`
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (runner *RunServer) Run(ctx server.Cmd) error {
	return runner.Broadcaster.WithBroadcaster(ctx, &runner.RunServer, func(changes *broadcaster.Broadcaster) error {
		return runner.Credential.withManager(ctx, changes, func(manager credential.CredentialManager, follow *follow) error {
			ctx.Logger().InfoContext(ctx.Context(), "Credentials", "backend", backend)
			ctx.Logger().WarnContext(ctx.Context(), "The credential API has no authentication")

			// The API publishes its changes, unless the backend follows them,
			// such as pg, whose table's trigger notifies of them
			var publisher httphandler.Publisher
			if follow == nil {
				publisher = changes
			}
			runner.register(ctx, manager, publisher)
			return runner.run(ctx, changes, follow)
		})
	})
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// register registers the configuration, with what the credential manager
// can do, which depends on its backend, the web UI, when it's served, or
// else a handler of / which isn't found, and the credential API, which
// publishes its changes, which the UI follows
func (runner *RunServer) register(ctx server.Cmd, manager credential.CredentialManager, publisher httphandler.Publisher) {
	runner.RunServer.Register(func(router *httprouter.Router) error {
		ui, err := runner.Frontend.RegisterUI(ctx, ctx.Logger(), router, runner.RunServer.OpenAPI,
			config.WithSection("credential", credential.FeaturesOf(backend, manager)),
		)
		if err != nil {
			return err
		}
		if !ui {
			if err := router.RegisterCatchAll("/", true); err != nil {
				return err
			}
		}
		var opts []httphandler.Opt
		if publisher != nil {
			opts = append(opts, httphandler.WithPublisher(publisher))
		}
		return httphandler.RegisterManagerHandlers(manager, false, opts...)(router)
	})
}

// run runs the broadcaster, the backend's follower of its changes, when it
// has one, and the server, until any of them stops. The server starts once
// the follower is ready, so no change is accepted before it would be
// published, and doesn't start when the follower fails.
func (runner *RunServer) run(ctx server.Cmd, changes *broadcaster.Broadcaster, follow *follow) error {
	group, groupctx := errgroup.WithContext(ctx.Context())
	group.Go(func() error {
		return changes.Run(groupctx)
	})
	if follow != nil {
		group.Go(func() error {
			return follow.run(groupctx)
		})
	}
	group.Go(func() error {
		if follow != nil {
			if err := follow.ready(groupctx); err != nil {
				return err
			}
		}
		return runner.RunServer.Run(ctx.WithContext(groupctx))
	})
	return group.Wait()
}
