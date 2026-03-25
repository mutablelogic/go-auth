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

type AuthClient struct {
	*client.Client
	Endpoint string
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func NewClient(endpoint string, opts ...client.ClientOpt) (*AuthClient, error) {
	self := new(AuthClient)
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

func (c *AuthClient) DoAuthWithContext(ctx context.Context, req client.Payload, v any) error {
	var auth *transport.Recorder
	if err := c.Client.DoWithContext(ctx, req, v, client.OptReqTransport(func(parent http.RoundTripper) http.RoundTripper {
		auth = transport.NewRecorder(parent)
		return auth
	})); err != nil {
		var code httpresponse.Err
		if ok := errors.As(err, &code); !ok {
			return err
		}
		if code == httpresponse.ErrNotAuthorized && auth != nil {
			return errors.Join(err, newAuthError(auth.Header()))
		}
		return err
	}
	return nil
}
