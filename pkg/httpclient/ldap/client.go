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
	// Packages
	auth "github.com/mutablelogic/go-auth/pkg/httpclient/auth"
	client "github.com/mutablelogic/go-client"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Client is a LDAP HTTP client that wraps the base HTTP client.
type Client struct {
	*auth.Client
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// New creates a new LDAP HTTP client with the given base URL and options.
func New(url string, opts ...client.ClientOpt) (*Client, error) {
	c := new(Client)
	if client, err := auth.New(url, opts...); err != nil {
		return nil, err
	} else {
		c.Client = client
	}
	return c, nil
}
