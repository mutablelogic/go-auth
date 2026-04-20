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

package auth

import (
	"context"
	"fmt"

	// Packages
	auth "github.com/mutablelogic/go-auth/auth/httpclient"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	server "github.com/mutablelogic/go-server"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type KeyCommands struct {
	CreateKey CreateKeyCommand `cmd:"" name:"key-create" help:"Create API key." group:"AUTH MANAGER"`
}

type CreateKeyCommand struct {
	schema.KeyMeta
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *CreateKeyCommand) Run(globals server.Cmd) error {
	return withManager(globals, "CreateKeyCommand", types.Stringify(cmd), func(ctx context.Context, client *auth.ManagerClient) error {
		key, err := client.CreateKey(ctx, cmd.KeyMeta)
		if err != nil {
			return err
		}
		fmt.Println(key)
		return nil
	})
}
