package oidc

import (
	// Packages
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// ProtectedResourceMetadata describes this server as an OAuth protected
// resource.
type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers,omitempty"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
	ResourceDocumentation  string   `json:"resource_documentation,omitempty"`
	ResourceName           string   `json:"resource_name,omitempty"`
}

///////////////////////////////////////////////////////////////////////////////
// STRINGIFY

func (c ProtectedResourceMetadata) String() string {
	return types.Stringify(c)
}
