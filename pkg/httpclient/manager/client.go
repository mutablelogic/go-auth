package manager

import (
	// Packages
	auth "github.com/djthorpe/go-auth/pkg/httpclient/auth"
	client "github.com/mutablelogic/go-client"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Client is a management HTTP client that wraps the base HTTP client.
type Client struct {
	*auth.Client
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// New creates a new management HTTP client with the given base URL and options.
func New(url string, opts ...client.ClientOpt) (*Client, error) {
	c := new(Client)
	if client, err := auth.New(url, opts...); err != nil {
		return nil, err
	} else {
		c.Client = client
	}
	return c, nil
}
