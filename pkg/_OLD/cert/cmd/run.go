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

package cmd

import (
	"context"

	// Packages
	server "github.com/mutablelogic/go-server"
	client "github.com/mutablelogic/go-server/pkg/cert/client"
)

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func run(ctx server.Cmd, fn func(context.Context, *client.Client) error) error {
	// Create a client
	provider, err := client.New(ctx.GetEndpoint("${CERT_PREFIX}").String(), ctx.GetClientOpts()...)
	if err != nil {
		return err
	}
	// Run the function
	return fn(ctx.Context(), provider)
}
