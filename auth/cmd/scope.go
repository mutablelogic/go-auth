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
	"os"

	// Packages
	auth "github.com/mutablelogic/go-auth/auth/httpclient"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	server "github.com/mutablelogic/go-server"
	tui "github.com/mutablelogic/go-server/pkg/tui"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type ScopeCommands struct {
	Scopes ListScopesCommand `cmd:"" name:"scopes" help:"Get Scopes." group:"AUTH MANAGER"`
}

type ListScopesCommand struct {
	schema.ScopeListRequest
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *ListScopesCommand) Run(globals server.Cmd) error {
	return withManager(globals, "ListScopesCommand", types.Stringify(cmd), func(ctx context.Context, client *auth.ManagerClient) error {
		scopes, err := client.ListScopes(ctx, cmd.ScopeListRequest)
		if err != nil {
			return err
		}

		scopeRows := make([]scopeRow, len(scopes.Body))
		for i, scope := range scopes.Body {
			scopeRows[i] = scopeRow(scope)
		}

		// Write out the scope table, and the summary
		tui.TableFor[scopeRow](tui.SetWidth(globals.IsTerm())).Write(os.Stdout, scopeRows...)
		tui.TableSummary("scopes", scopes.Count, scopes.Offset, scopes.Limit).Write(os.Stdout)

		// Return success
		return nil
	})
}

///////////////////////////////////////////////////////////////////////////////
// TABLE OUTPUT

type scopeRow string

func (r scopeRow) Header() []string {
	return []string{"Scope"}
}

func (r scopeRow) Cell(i int) string {
	return string(r)
}

func (r scopeRow) Width(i int) int {
	return 0
}
