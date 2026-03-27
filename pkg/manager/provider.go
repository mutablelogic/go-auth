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
	"net/http"
	"net/url"

	// Packages
	auth "github.com/djthorpe/go-auth"
	provider "github.com/djthorpe/go-auth/pkg/provider"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type HTTPHandler struct {
	Path    string
	Handler http.HandlerFunc
	Spec    *openapi.PathItem
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Provider returns a registered provider by key.
func (m *Manager) Provider(key string) (provider.Provider, error) {
	if !types.IsIdentifier(key) {
		return nil, auth.ErrInvalidProvider.Withf("invalid provider key: %q", key)
	}

	if provider, ok := m.providers[key]; !ok || provider == nil {
		return nil, auth.ErrInvalidProvider.Withf("unsupported provider %q", key)
	} else {
		return provider, nil
	}
}

// ProviderPath returns the mount path for a registered provider browser handler.
func (m *Manager) ProviderPath(key string) (string, error) {
	provider, err := m.Provider(key)
	if err != nil {
		return "", err
	}
	return ProviderPath(provider.Key())
}

// HTTPHandlers returns all provider-owned browser handlers.
func (m *Manager) HTTPHandlers() []HTTPHandler {
	handlers := make([]HTTPHandler, 0, len(m.providers))
	for _, provider := range m.providers {
		if provider == nil {
			continue
		}

		if handler, spec := provider.HTTPHandler(); handler == nil {
			continue
		} else if path, err := ProviderPath(provider.Key()); err != nil {
			continue
		} else {
			handlers = append(handlers, HTTPHandler{
				Path:    path,
				Handler: handler,
				Spec:    spec,
			})
		}
	}
	return handlers
}

// ProviderPath returns the mount path for a provider browser handler key.
func ProviderPath(key string) (string, error) {
	return url.JoinPath("auth", "provider", key)
}
