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

	// Packages
	auth "github.com/mutablelogic/go-auth/auth/httpclient"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	server "github.com/mutablelogic/go-server"
	attribute "go.opentelemetry.io/otel/attribute"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type ManagerCommands struct {
	ProviderCommands
	ScopeCommands
	UserCommands
	GroupCommands
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC FUNCTIONS

// managerClientFor returns manager client configured from the global HTTP flags.
func managerClientFor(ctx server.Cmd) (*auth.ManagerClient, string, error) {
	endpoint, opts, err := ctx.ClientEndpoint()
	if err != nil {
		return nil, "", err
	}

	// Create a manager client
	client, err := auth.Manager(endpoint, NewTokenStore(ctx), opts...)
	if err != nil {
		return nil, "", err
	}

	// Return the client and endpoint
	return client, endpoint, nil
}

// withManager is a helper function to create a manager client and an OTEL span, then call the provided function with it.
func withManager(ctx server.Cmd, name, args string, fn func(context.Context, *auth.ManagerClient) error) (err error) {
	// Create a span for the command
	spanctx, endSpan := otel.StartSpan(ctx.Tracer(), ctx.Context(), name,
		attribute.String("cmd", args),
	)
	defer func() { endSpan(err) }()

	client, _, err := managerClientFor(ctx)
	if err != nil {
		return err
	}
	return fn(spanctx, client)
}
