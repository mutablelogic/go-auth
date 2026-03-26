package oidc

import (
	// Packages
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const OAuthClientKeyLocal = "local"

///////////////////////////////////////////////////////////////////////////////
// TYPES

// PublicClientConfiguration contains the upstream provider details that are
// safe to expose to clients that need to initiate authentication.
type PublicClientConfiguration struct {
	Issuer   string `json:"issuer"`
	ClientID string `json:"client_id,omitempty"`
	Provider string `json:"provider"`
}

// PublicClientConfigurations contains shareable client configuration keyed by
// provider or role name.
type PublicClientConfigurations map[string]PublicClientConfiguration

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

// ClientConfiguration contains the full upstream provider configuration,
// including the client secret that must remain server-side.
type ClientConfiguration struct {
	PublicClientConfiguration
	ClientSecret string `json:"client_secret,omitempty"`
}

// ClientConfigurations contains all configured OAuth clients keyed by
// provider or role name.
type ClientConfigurations map[string]ClientConfiguration

///////////////////////////////////////////////////////////////////////////////
// STRINGIFY

func (c ProtectedResourceMetadata) String() string {
	return types.Stringify(c)
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Public returns the shareable subset of the client configuration.
func (cfg ClientConfiguration) Public() PublicClientConfiguration {
	return cfg.PublicClientConfiguration
}

// Public returns the shareable subset of all configured clients.
func (cfg ClientConfigurations) Public() PublicClientConfigurations {
	result := make(PublicClientConfigurations, len(cfg))
	for key, value := range cfg {
		result[key] = value.Public()
	}
	return result
}
