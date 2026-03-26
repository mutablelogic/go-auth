package main

import (
	// Packages
	managerclient "github.com/djthorpe/go-auth/pkg/httpclient/manager"
	server "github.com/mutablelogic/go-server"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type clients struct {
	manager *managerclient.Client
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC FUNCTIONS

// clientFor returns auth and management clients configured from the global HTTP flags.
func clientFor(ctx server.Cmd) (*clients, string, error) {
	endpoint, opts, err := ctx.ClientEndpoint()
	if err != nil {
		return nil, "", err
	}
	manager, err := managerclient.New(endpoint, opts...)
	if err != nil {
		return nil, "", err
	}
	return &clients{manager: manager}, endpoint, nil
}
