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
	"errors"
	"net/http"
	"strings"

	// Packages
	client "github.com/mutablelogic/go-client"
	transport "github.com/mutablelogic/go-client/pkg/transport"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type Client struct {
	*client.Client
	Endpoint string
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func New(endpoint string, opts ...client.ClientOpt) (*Client, error) {
	self := new(Client)
	if client, err := client.New(append([]client.ClientOpt{client.OptEndpoint(endpoint)}, opts...)...); err != nil {
		return nil, err
	} else {
		self.Client = client
		self.Endpoint = strings.TrimSpace(endpoint)
	}

	// Return success
	return self, nil
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - AUTH ERRORS

// DoAuthWithContext performs the supplied request, and if the response is 401 Unauthorized, it parses the WWW-Authenticate header
// and returns an AuthError with the header values.
func (c *Client) DoAuthWithContext(ctx context.Context, req client.Payload, v any, opt ...client.RequestOpt) error {
	var auth *transport.Recorder

	// Add the recorder transport to the request options
	opts := append(opt, client.OptReqTransport(func(parent http.RoundTripper) http.RoundTripper {
		auth = transport.NewRecorder(parent)
		return auth
	}))

	// Perform the request, and parse the WWW-Authenticate header if the response is 401 Unauthorized
	if err := c.Client.DoWithContext(ctx, req, v, opts...); err != nil {
		var code httpresponse.Err
		if ok := errors.As(err, &code); !ok {
			return err
		}
		if code == httpresponse.ErrNotAuthorized && auth != nil {
			return errors.Join(err, newAuthError(auth.Header()))
		}
		return err
	}

	// Otherwise, return success
	return nil
}
