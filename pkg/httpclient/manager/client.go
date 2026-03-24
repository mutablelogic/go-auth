package manager

import (
	// Packages
	client "github.com/mutablelogic/go-client"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Client is a management HTTP client that wraps the base HTTP client.
type Client struct {
	*client.Client
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// New creates a new management HTTP client with the given base URL and options.
func New(url string, opts ...client.ClientOpt) (*Client, error) {
	c := new(Client)
	if client, err := client.New(append(opts, client.OptEndpoint(url))...); err != nil {
		return nil, err
	} else {
		c.Client = client
	}
	return c, nil
}
