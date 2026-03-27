//go:build !client

package main

import (
	"crypto/rsa"
	"fmt"
	"strings"

	// Packages
	providerpkg "github.com/djthorpe/go-auth/pkg/provider"
	localprovider "github.com/djthorpe/go-auth/pkg/provider/local"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// LocalProviderFlags controls whether the built-in local provider is registered.
type LocalProviderFlags struct {
	Enabled bool `name:"local-provider" help:"Enable the built-in local identity provider browser flow." default:"false" negatable:""`
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func (flags LocalProviderFlags) NewProvider(privateKey *rsa.PrivateKey, issuer string) (providerpkg.Provider, error) {
	if !flags.Enabled {
		return nil, nil
	}
	if privateKey == nil {
		return nil, fmt.Errorf("private key is required")
	}
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}
	return localprovider.New(issuer, privateKey)
}
