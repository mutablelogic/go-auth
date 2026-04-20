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
	"crypto/rsa"

	// Packages
	provider "github.com/mutablelogic/go-auth/auth/provider"
	local "github.com/mutablelogic/go-auth/auth/provider/local"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// LocalProviderFlags controls whether the built-in local provider is registered.
type LocalProviderFlags struct {
	Enabled bool `name:"enabled" help:"Enable the built-in local identity provider browser flow." default:"false" negatable:""`
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func (flags LocalProviderFlags) NewProvider(privateKey *rsa.PrivateKey, issuer string) (provider.Provider, error) {
	if !flags.Enabled {
		return nil, nil
	}
	return local.New(issuer, privateKey)
}
