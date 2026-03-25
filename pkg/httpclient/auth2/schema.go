package auth

import (
	// Packages
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type ProtectedResourceDiscovery struct {
	Challenge            *AuthError                      `json:"challenge,omitempty"`
	ResourceMetadata     *oidc.ProtectedResourceMetadata `json:"resource_metadata,omitempty"`
	AuthorizationServers []AuthorizationServerInfo       `json:"authorization_servers,omitempty"`
	Warnings             []string                        `json:"warnings,omitempty"`
}

type AuthorizationServerInfo struct {
	Issuer       string                          `json:"issuer"`
	OIDC         *oidc.Configuration             `json:"oidc,omitempty"`
	OAuth        *OAuthAuthorizationServer       `json:"oauth,omitempty"`
	ProviderHint oidc.PublicClientConfigurations `json:"provider_hint,omitempty"`
	Warnings     []string                        `json:"warnings,omitempty"`
}

type OAuthAuthorizationServer struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                     string   `json:"token_endpoint,omitempty"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	RevocationEndpoint                string   `json:"revocation_endpoint,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported,omitempty"`
	ResponseModesSupported            []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`
}
