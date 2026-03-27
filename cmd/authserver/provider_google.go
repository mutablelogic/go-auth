//go:build !client

package main

import (
	"strings"

	// Packages
	provider "github.com/djthorpe/go-auth/pkg/provider"
	googleprovider "github.com/djthorpe/go-auth/pkg/provider/google"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// GoogleFlags contains configuration for the Google identity provider.
type GoogleProviderFlags struct {
	ClientID     string `name:"client-id" env:"GOOGLE_CLIENT_ID" help:"Google OAuth client ID."`
	ClientSecret string `name:"client-secret" env:"GOOGLE_CLIENT_SECRET" help:"Google OAuth client secret."`
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func (flags GoogleProviderFlags) NewProvider() (provider.Provider, error) {
	clientID := strings.TrimSpace(flags.ClientID)
	clientSecret := strings.TrimSpace(flags.ClientSecret)
	if clientID == "" || clientSecret == "" {
		return nil, nil
	}
	return googleprovider.New(clientID, clientSecret)
}
