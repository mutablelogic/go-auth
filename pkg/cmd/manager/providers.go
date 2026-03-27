package manager

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	manager "github.com/djthorpe/go-auth/pkg/httpclient/manager"
	server "github.com/mutablelogic/go-server"
)

var providersOutput io.Writer = os.Stdout

///////////////////////////////////////////////////////////////////////////////
// TYPES

type ProvidersCommand struct{}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *ProvidersCommand) Run(ctx server.Cmd) error {
	return withUnauthenticatedClient(ctx, func(managerClient *manager.Client, endpoint string) error {
		config, err := managerClient.Config(ctx.Context())
		if err != nil {
			return err
		}
		data, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(providersOutput, string(data)); err != nil {
			return err
		}
		return nil
	})
}
