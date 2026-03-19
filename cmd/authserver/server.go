//go:build !client

package main

import (
	"fmt"

	// Packages
	httphandler "github.com/djthorpe/go-auth/pkg/httphandler"
	manager "github.com/djthorpe/go-auth/pkg/manager"
	server "github.com/mutablelogic/go-server"
	cmd "github.com/mutablelogic/go-server/pkg/cmd"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
)

type ServerCommands struct {
	RunServer RunServer `cmd:"" name:"run" help:"Run server." group:"SERVER"`
}

type RunServer struct {
	PostgresFlags
	cmd.RunServer
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (server *RunServer) Run(ctx server.Cmd) error {
	return server.WithManager(ctx, func(manager *manager.Manager, v string) error {

		// Register HTTP handlers
		server.RunServer.Register(func(router *httprouter.Router) error {
			return httphandler.RegisterHandlers(manager, router)
		})

		// Run the server
		return server.RunServer.Run(ctx)
	})
}

// WithManager creates the resource manager, registers all resource instances
// (logger, otel, handlers, router) in dependency order, invokes fn, then
// closes the manager regardless of whether fn returned an error.
func (server *RunServer) WithManager(ctx server.Cmd, fn func(*manager.Manager, string) error) error {
	// Connect to the database, if configured
	conn, err := server.Connect(ctx)
	if err != nil {
		return err
	} else if conn == nil {
		return fmt.Errorf("database connection is required")
	}

	// Create an auth manager
	manager, err := manager.New(ctx.Context(), conn, "")
	if err != nil {
		return err
	}
	defer manager.Close()

	// Invoke the function with the manager and version string
	return fn(manager, "v1")
}
