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

//go:build !client

package main

import (
	"strings"

	// Packages
	provider "github.com/mutablelogic/go-auth/auth/provider"
	googleprovider "github.com/mutablelogic/go-auth/auth/provider/google"
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
