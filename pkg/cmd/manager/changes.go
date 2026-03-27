package manager

import (
	"context"
	"errors"
	"fmt"

	// Packages
	manager "github.com/djthorpe/go-auth/pkg/httpclient/manager"
	schema "github.com/djthorpe/go-auth/schema"
	server "github.com/mutablelogic/go-server"
)

type ChangesCommands struct {
	Changes ChangesCommand `cmd:"" name:"changes" help:"Stream protected change notifications until interrupted." group:"USER MANAGER"`
}

type ChangesCommand struct{}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *ChangesCommand) Run(ctx server.Cmd) error {
	return WithClient(ctx, func(manager *manager.Client, endpoint string) error {
		err := manager.ListenChanges(ctx.Context(), func(change schema.ChangeNotification) error {
			fmt.Println(change)
			return nil
		})
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	})
}
