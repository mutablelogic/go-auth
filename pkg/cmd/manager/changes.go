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

package manager

import (
	"context"
	"errors"
	"fmt"

	// Packages
	manager "github.com/djthorpe/go-auth/pkg/httpclient/manager"
	schema "github.com/djthorpe/go-auth/schema/auth"
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
