package main

import (
	// Packages
	httpclient "github.com/djthorpe/go-auth/pkg/httpclient"
	server "github.com/mutablelogic/go-server"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC FUNCTIONS

// clientFor returns an httpclient.Client configured from the global HTTP flags.
func clientFor(ctx server.Cmd) (*httpclient.Client, string, error) {
	endpoint, opts, err := ctx.ClientEndpoint()
	if err != nil {
		return nil, "", err
	}
	client, err := httpclient.New(endpoint, opts...)
	if err != nil {
		return nil, "", err
	}
	return client, endpoint, nil
}
