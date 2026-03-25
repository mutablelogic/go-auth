package main

import (
	"context"
	"errors"
	"fmt"

	// Packages
	schema "github.com/djthorpe/go-auth/schema"
	server "github.com/mutablelogic/go-server"
)

type ChangesCommands struct {
	Changes ChangesCommand `cmd:"" name:"changes" help:"Stream protected change notifications until interrupted." group:"USERS & GROUPS"`
}

type ChangesCommand struct{}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *ChangesCommand) Run(ctx server.Cmd) error {
	clients, _, err := clientFor(ctx)
	if err != nil {
		return err
	}

	err = clients.manager.ListenChanges(ctx.Context(), func(change schema.ChangeNotification) error {
		fmt.Println(change)
		return nil
	})
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
