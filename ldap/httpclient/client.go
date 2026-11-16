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

// Package httpclient calls the LDAP API, which ldap/httphandler serves
package httpclient

import (
	"context"
	"net/url"
	"strings"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	client "github.com/mutablelogic/go-client"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Client calls the LDAP API, which ldap/httphandler serves
type Client struct {
	*client.Client
}

// textRequest is a request whose body is plain text, such as a password
type textRequest struct {
	*strings.Reader
	method string
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

// The path of the LDAP API, under the API's
const pathLDAP = "ldap"

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// New returns a client of the LDAP API at the URL, such as
// "http://localhost:8080/api"
func New(url string, opts ...client.ClientOpt) (*Client, error) {
	c, err := client.New(append(opts, client.OptEndpoint(url))...)
	if err != nil {
		return nil, err
	}
	return &Client{Client: c}, nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// get decodes the response of a GET of the path, under ldap/, with the
// query, into the response
func get[T any](ctx context.Context, c *Client, query any, path ...any) (*T, error) {
	var response T
	opts := []client.RequestOpt{client.OptPath(append([]any{pathLDAP}, path...)...)}
	if q, ok := query.(interface{ Query() url.Values }); ok {
		opts = append(opts, client.OptQuery(q.Query()))
	}
	if err := c.DoWithContext(ctx, client.MethodGet, &response, opts...); err != nil {
		return nil, auth.ClientError(err)
	}
	return &response, nil
}

// send sends the body as JSON, or no body, when it's nil, with the method,
// to the path, under ldap/, and decodes the response
func send[T any](ctx context.Context, c *Client, method string, body any, opts []client.RequestOpt, path ...any) (*T, error) {
	var req client.Payload = client.NewRequestEx(method, types.ContentTypeJSON)
	if body != nil {
		var err error
		if req, err = client.NewJSONRequestEx(method, body, types.ContentTypeJSON); err != nil {
			return nil, err
		}
	}
	var response T
	opts = append(opts, client.OptPath(append([]any{pathLDAP}, path...)...))
	if err := c.DoWithContext(ctx, req, &response, opts...); err != nil {
		return nil, auth.ClientError(err)
	}
	return &response, nil
}

func (r textRequest) Method() string { return r.method }
func (r textRequest) Accept() string { return types.ContentTypeJSON }
func (r textRequest) Type() string   { return types.ContentTypeTextPlain }
