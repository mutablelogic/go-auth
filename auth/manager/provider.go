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

package manager

import (
	"maps"
	"net/url"
	"slices"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	provider "github.com/mutablelogic/go-auth/auth/provider"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// WithProvider sets an identity provider for the manager.
func (m *Manager) WithProvider(provider provider.Provider) error {
	m.Lock()
	defer m.Unlock()

	// We allow nil providers here
	if provider == nil {
		return nil
	}

	// Register the provider
	return WithProvider(provider)(&m.opt)
}

// WithIssuer sets the issuer URL for the manager's OIDC configuration.
func (m *Manager) WithIssuer(issuer string) error {
	m.Lock()
	defer m.Unlock()
	return WithIssuer(issuer)(&m.opt)
}

// ProviderKeys returns the keys of all registered providers.
func (m *Manager) ProviderKeys() []string {
	m.Lock()
	defer m.Unlock()
	return slices.Collect(maps.Keys(m.providers))
}

// Provider returns a registered provider by key.
func (m *Manager) Provider(key string) (provider.Provider, error) {
	m.Lock()
	defer m.Unlock()

	if !types.IsIdentifier(key) {
		return nil, auth.ErrInvalidProvider.Withf("invalid provider key: %q", key)
	} else if provider, ok := m.providers[key]; !ok || provider == nil {
		return nil, auth.ErrInvalidProvider.Withf("unsupported provider %q", key)
	} else {
		return provider, nil
	}
}

// ProviderPath returns the mount path for a registered provider browser handler.
func (m *Manager) ProviderPath(key string) (string, error) {
	// Validate the provider key and return the path
	provider, err := m.Provider(key)
	if err != nil {
		return "", err
	} else {
		return url.JoinPath("auth", "provider", provider.Key())
	}
}
