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

type ProviderCommands struct {
	Providers ListProvidersCommand `cmd:"" name:"providers" help:"Get Providers." group:"USER MANAGER"`
}

type ListProvidersCommand struct{}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *ListProvidersCommand) Run(ctx server.Cmd) error {
	return withManager(ctx, func(client *auth.ManagerClient, endpoint string) error {
		providers, err := client.Config(ctx.Context())
		if err != nil {
			return err
		}

		providerRows := make([]providerRow, 0, len(providers))
		for key, provider := range providers {
			providerRows = append(providerRows, providerRow{
				Key:      key,
				Provider: provider,
			})
		}

		// Write out the provider table, and the summary
		tui.TableFor[providerRow]().Write(os.Stdout, providerRows...)
		tui.TableSummary("providers", uint(len(providerRows)), 0, nil).Write(os.Stdout)

		// Return success
		return nil
	})
}

type providerRow struct {
	Key      string
	Provider schema.PublicClientConfiguration
}

func (r providerRow) Header() []string {
	return []string{"Provider", "Config"}
}

func (r providerRow) Cell(i int) string {
	switch i {
	case 0:
		return r.Key
	case 1:
		return types.Stringify(r.Provider)
	default:
		return ""
	}
}

func (r providerRow) Width(i int) int {
	return 0
}
