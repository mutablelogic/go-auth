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

package ldap

import (
	"net/http"

	// Packages
	auth "github.com/mutablelogic/go-auth/auth/httpclient"
	ldap "github.com/mutablelogic/go-auth/ldap/httpclient"
	client "github.com/mutablelogic/go-client"
	server "github.com/mutablelogic/go-server"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC FUNCTIONS

// WithClient returns auth client configured from the global HTTP flags.
func WithClient(ctx server.Cmd, fn func(*ldap.Client, string) error) error {
	return withClient(ctx, true, fn)
}

func withUnauthenticatedClient(ctx server.Cmd, fn func(*ldap.Client, string) error) error {
	return withClient(ctx, false, fn)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE FUNCTIONS

func withClient(ctx server.Cmd, authenticated bool, fn func(*ldap.Client, string) error) error {
	endpoint, opts, err := ctx.ClientEndpoint()
	if err != nil {
		return err
	}
	authClient, err := auth.New(endpoint, opts...)
	if err != nil {
		return err
	}
	if authenticated {
		opts = append(opts, client.OptTransport(func(parent http.RoundTripper) http.RoundTripper {
			return newAuthTransport(parent, ctx, authClient)
		}))
	}
	client, err := ldap.New(endpoint, opts...)
	if err != nil {
		return err
	}
	return fn(client, endpoint)
}
