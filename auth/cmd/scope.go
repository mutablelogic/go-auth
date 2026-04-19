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
	"fmt"

	// Packages
	auth "github.com/mutablelogic/go-auth/auth/httpclient"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	server "github.com/mutablelogic/go-server"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type ScopeCommands struct {
	Scopes ListScopesCommand `cmd:"" name:"scopes" help:"Get Scopes." group:"USER MANAGER"`
}

type ListScopesCommand struct {
	schema.ScopeListRequest
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *ListScopesCommand) Run(ctx server.Cmd) error {
	return withManager(ctx, func(client *auth.ManagerClient, endpoint string) error {
		scopes, err := client.ListScopes(ctx.Context(), cmd.ScopeListRequest)
		if err != nil {
			return err
		}
		fmt.Println(scopes)
		return nil
	})
}
