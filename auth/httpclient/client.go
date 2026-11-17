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

package httpclient

import (
	"context"
	"net/http"
	"slices"
	"strings"

	// Packages
	client "github.com/mutablelogic/go-client"
	transport "github.com/mutablelogic/go-client/pkg/transport"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Client is a client of a resource, at its endpoint, with go-client, whose
// requests which aren't authorized return an AuthError, and which
// discovers how a token for the resource is got
type Client struct {
	*client.Client
	endpoint string

	// The client of metadata, as it's discovered, which is go-client's,
	// without the options, so its requests, which can be to another origin,
	// such as an authorization server's, aren't sent the credentials, and
	// headers, the resource's are
	metadata *client.Client
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// New returns a client of the resource at the endpoint, with go-client's
// options, such as a token, which the endpoint is applied after, so an
// option can't change it
func New(endpoint string, opts ...client.ClientOpt) (*Client, error) {
	return NewWithDiscovery(endpoint, opts)
}

// NewWithDiscovery returns a client of the resource at the endpoint, as New
// does, with the options of its requests, and of those which discover how
// it's authorized, register a client, and get a token, which can be to
// another origin, such as a trace, a tracer, or a timeout, which mustn't
// be credentials, such as the resource's token
func NewWithDiscovery(endpoint string, opts []client.ClientOpt, discovery ...client.ClientOpt) (*Client, error) {
	endpoint = strings.TrimSpace(endpoint)
	c, err := client.New(append(slices.Clone(opts), client.OptEndpoint(endpoint))...)
	if err != nil {
		return nil, err
	}
	metadata, err := client.New(append(slices.Clone(discovery), client.OptEndpoint(endpoint))...)
	if err != nil {
		return nil, err
	}
	return &Client{Client: c, endpoint: endpoint, metadata: metadata}, nil
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Endpoint returns the endpoint of the resource
func (c *Client) Endpoint() string {
	return c.endpoint
}

// DoAuthWithContext makes the request, as DoWithContext does, and returns an
// AuthError, with the server's challenge, when it isn't authorized, which
// is a 401 Unauthorized response with a WWW-Authenticate header, so how a
// token is got for it can be discovered, with DiscoverWithError
func (c *Client) DoAuthWithContext(ctx context.Context, req client.Payload, v any, opts ...client.RequestOpt) error {
	var recorder *transport.Recorder
	opts = append(opts, client.OptReqTransport(func(parent http.RoundTripper) http.RoundTripper {
		recorder = transport.NewRecorder(parent)
		return recorder
	}))
	if err := c.Client.DoWithContext(ctx, req, v, opts...); err != nil {
		if recorder != nil && recorder.StatusCode() == http.StatusUnauthorized {
			if authErr := ParseChallenge(recorder.Header()); authErr != nil {
				return authErr
			}
		}
		return err
	}
	return nil
}
