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
