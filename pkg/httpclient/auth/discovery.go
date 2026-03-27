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

package auth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	// Packages
	auth "github.com/djthorpe/go-auth"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	client "github.com/mutablelogic/go-client"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type ServerMetadata struct {
	Issuer string                  `json:"issuer,omitempty"`
	Oidc   oidc.OIDCConfiguration  `json:"oidc,omitzero"`
	OAuth  oidc.OAuthConfiguration `json:"oauth,omitzero"`
}

type Config struct {
	oidc.ProtectedResourceMetadata `json:"protected_resource_metadata,omitempty"`
	AuthorizationServers           []ServerMetadata `json:"authorization_servers,omitempty"`
}

///////////////////////////////////////////////////////////////////////////////
// STRINGIFY

func (c Config) String() string {
	return types.Stringify(c)
}

// AuthorizationServerForFlow selects a discovered authorization server that
// advertises an authorization endpoint.
func (c *Config) AuthorizationServerForFlow() (*ServerMetadata, error) {
	if c == nil || len(c.AuthorizationServers) == 0 {
		return nil, fmt.Errorf("authorization server metadata is required")
	}
	for index := range c.AuthorizationServers {
		serverMeta := &c.AuthorizationServers[index]
		if strings.TrimSpace(serverMeta.Oidc.AuthorizationEndpoint) != "" || strings.TrimSpace(serverMeta.OAuth.AuthorizationEndpoint) != "" {
			return serverMeta, nil
		}
	}
	return nil, fmt.Errorf("no authorization endpoint is advertised")
}

// AuthorizationServerForRegistration selects a discovered authorization server
// that can be used for dynamic client registration.
func (c *Config) AuthorizationServerForRegistration() (*ServerMetadata, error) {
	if c == nil || len(c.AuthorizationServers) == 0 {
		return nil, fmt.Errorf("authorization server metadata is required")
	}
	for index := range c.AuthorizationServers {
		serverMeta := &c.AuthorizationServers[index]
		if registrationEndpoint(serverMeta) != "" &&
			(strings.TrimSpace(serverMeta.Oidc.AuthorizationEndpoint) != "" || strings.TrimSpace(serverMeta.OAuth.AuthorizationEndpoint) != "") {
			return serverMeta, nil
		}
	}
	for index := range c.AuthorizationServers {
		serverMeta := &c.AuthorizationServers[index]
		if registrationEndpoint(serverMeta) != "" {
			return serverMeta, nil
		}
	}
	return nil, fmt.Errorf("no registration endpoint is advertised")
}

// AuthorizationServerForUserInfo selects a discovered authorization server
// that advertises a userinfo endpoint.
func (c *Config) AuthorizationServerForUserInfo() (*ServerMetadata, error) {
	if c == nil || len(c.AuthorizationServers) == 0 {
		return nil, fmt.Errorf("authorization server metadata is required")
	}
	for index := range c.AuthorizationServers {
		serverMeta := &c.AuthorizationServers[index]
		if strings.TrimSpace(serverMeta.Oidc.UserInfoEndpoint) != "" {
			return serverMeta, nil
		}
	}
	return nil, fmt.Errorf("no userinfo endpoint is advertised")
}

// AuthorizationCodeConfig converts the selected authorization server metadata
// into the minimal OIDC/OAuth configuration needed to build an auth code flow.
func (c *Config) AuthorizationCodeConfig() (oidc.BaseConfiguration, error) {
	serverMeta, err := c.AuthorizationServerForFlow()
	if err != nil {
		return oidc.BaseConfiguration{}, err
	}
	return serverMeta.AuthorizationCodeConfig()
}

// AuthorizationCodeConfig converts discovered server metadata into a base
// configuration suitable for authorization code flows.
func (serverMeta *ServerMetadata) AuthorizationCodeConfig() (oidc.BaseConfiguration, error) {
	if serverMeta == nil {
		return oidc.BaseConfiguration{}, fmt.Errorf("authorization server metadata is required")
	}
	if strings.TrimSpace(serverMeta.Oidc.AuthorizationEndpoint) != "" {
		config := serverMeta.Oidc.BaseConfiguration
		if strings.TrimSpace(config.Issuer) == "" {
			config.Issuer = strings.TrimSpace(serverMeta.Issuer)
		}
		config.NonceSupported = true
		return config, nil
	}
	if strings.TrimSpace(serverMeta.OAuth.AuthorizationEndpoint) != "" {
		config := serverMeta.OAuth.BaseConfiguration
		if strings.TrimSpace(config.Issuer) == "" {
			config.Issuer = strings.TrimSpace(serverMeta.Issuer)
		}
		config.NonceSupported = false
		return config, nil
	}
	return oidc.BaseConfiguration{}, fmt.Errorf("no authorization endpoint is advertised")
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// DiscoverWithError resolves auth metadata from an auth challenge.
func (c *Client) DiscoverWithError(ctx context.Context, err error) (*Config, error) {
	var authErr *AuthError
	if ok := errors.As(err, &authErr); !ok || authErr == nil {
		return nil, err
	}

	// Attempt discovery using resource_metadata hint, if present.
	if endpoint := strings.TrimSpace(authErr.Get("resource_metadata")); endpoint != "" {
		config, resourceErr := c.discoverFromResourceMetadata(ctx, endpoint)
		if resourceErr == nil && len(config.AuthorizationServers) > 0 {
			return config, nil
		}
		if fallback, fallbackErr := c.discoverWithoutResourceMetadata(ctx, authErr); fallbackErr == nil {
			if config != nil {
				fallback.ProtectedResourceMetadata = config.ProtectedResourceMetadata
			}
			return fallback, nil
		}
		if resourceErr != nil {
			return nil, resourceErr
		}
		return config, nil
	}

	return c.discoverWithoutResourceMetadata(ctx, authErr)
}

// Discover resolves auth server metadata directly from an issuer URL.
func (c *Client) Discover(ctx context.Context, issuer string) (*Config, error) {
	var config Config
	for _, endpoint := range resourceMetadataCandidates(issuer) {
		if err := c.DoWithContext(ctx, nil, &config.ProtectedResourceMetadata, client.OptReqEndpoint(endpoint)); err == nil {
			break
		} else {
			var httpErr httpresponse.Err
			if errors.As(err, &httpErr) && (httpErr == httpresponse.ErrNotFound || httpErr == httpresponse.ErrNotAuthorized) {
				continue
			}
			return nil, fmt.Errorf("fetch resource metadata from %q: %w", endpoint, err)
		}
	}

	seen := map[string]struct{}{}
	c.appendDiscoveredServers(ctx, &config, seen, config.ProtectedResourceMetadata.AuthorizationServers...)

	// If there is no protected resource metadata, we can attempt to discover directly from the issuer
	if len(config.ProtectedResourceMetadata.AuthorizationServers) == 0 {
		c.appendDiscoveredServers(ctx, &config, seen, issuer)
	}

	// Interoperability fallback for providers that host resources and auth metadata on different subdomains.
	if len(config.AuthorizationServers) == 0 {
		c.appendDiscoveredServers(ctx, &config, seen, interoperabilityIssuerCandidates(issuer)...)
	}

	return &config, nil
}

// DiscoverFromIssuer resolves authorization server metadata directly from a
// known issuer URL without first probing protected-resource metadata.
func (c *Client) DiscoverFromIssuer(ctx context.Context, issuer string) (*Config, error) {
	serverMeta, err := c.discoverFromIssuer(ctx, issuer)
	if err != nil {
		return nil, err
	}
	config := &Config{}
	if serverMeta != nil {
		config.AuthorizationServers = append(config.AuthorizationServers, types.Value(serverMeta))
	}
	return config, nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func (c *Client) discoverWithoutResourceMetadata(ctx context.Context, authErr *AuthError) (*Config, error) {
	if authErr == nil {
		return nil, auth.ErrNotImplemented
	}

	config := new(Config)
	seen := map[string]struct{}{}
	c.appendDiscoveredServers(ctx, config, seen, authServerCandidates(authErr)...)
	if len(config.AuthorizationServers) == 0 {
		c.appendDiscoveredServers(ctx, config, seen, interoperabilityIssuerCandidates(c.Endpoint)...)
	}

	if len(config.AuthorizationServers) == 0 {
		return nil, fmt.Errorf("authorization server metadata is required")
	}
	return config, nil
}

func (c *Client) discoverFromResourceMetadata(ctx context.Context, endpoint string) (*Config, error) {
	resource, err := c.discoverWithResourceMetadata(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	config := &Config{ProtectedResourceMetadata: types.Value(resource)}
	c.appendDiscoveredServers(ctx, config, map[string]struct{}{}, resource.AuthorizationServers...)
	return config, nil
}

func (c *Client) appendDiscoveredServers(ctx context.Context, config *Config, seen map[string]struct{}, issuers ...string) {
	if config == nil {
		return
	}
	if seen == nil {
		seen = map[string]struct{}{}
	}
	for _, issuer := range issuers {
		issuer = strings.TrimSpace(issuer)
		if issuer == "" {
			continue
		}
		if _, ok := seen[issuer]; ok {
			continue
		}
		seen[issuer] = struct{}{}
		if serverConfig, err := c.discoverFromIssuer(ctx, issuer); err == nil {
			config.AuthorizationServers = append(config.AuthorizationServers, types.Value(serverConfig))
		}
	}
}

// discoverFromResourceMetadata fetches discovery from an explicit metadata endpoint.
func (c *Client) discoverWithResourceMetadata(ctx context.Context, endpoint string) (*oidc.ProtectedResourceMetadata, error) {
	var resource oidc.ProtectedResourceMetadata
	if err := c.DoWithContext(ctx, nil, &resource, client.OptReqEndpoint(endpoint)); err != nil {
		return nil, err
	}
	return types.Ptr(resource), nil
}

func authServerCandidates(authErr *AuthError) []string {
	if authErr == nil {
		return nil
	}
	return collectIssuerCandidates(
		explicitIssuerCandidates(authErr),
		authorizationURIIssuerCandidates(authErr),
		[]string{absoluteRealmURL(authErr)},
	)
}

func explicitIssuerCandidates(authErr *AuthError) []string {
	if authErr == nil {
		return nil
	}
	result := make([]string, 0, 3)
	for _, key := range []string{"issuer", "authorization_server", "authorization_server_uri"} {
		value := absoluteURL(authErr.Get(key))
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}

func authorizationURIIssuerCandidates(authErr *AuthError) []string {
	if authErr == nil {
		return nil
	}
	authorizationURI := strings.TrimSpace(authErr.Get("authorization_uri"))
	uri, err := url.Parse(authorizationURI)
	if err != nil || uri.Scheme == "" || uri.Host == "" {
		return nil
	}
	path := strings.TrimRight(uri.Path, "/")
	for _, suffix := range []string{"/oauth2/v2.0/authorize", "/o/oauth2/v2/auth", "/oauth2/authorize", "/oauth/authorize", "/authorize", "/auth"} {
		if strings.HasSuffix(path, suffix) {
			path = strings.TrimSuffix(path, suffix)
			break
		}
	}
	issuer := &url.URL{Scheme: uri.Scheme, Host: uri.Host, Path: path}
	return []string{issuer.String()}
}

func absoluteRealmURL(authErr *AuthError) string {
	if authErr == nil {
		return ""
	}
	return absoluteURL(authErr.Get("realm"))
}

func absoluteURL(raw string) string {
	uri, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || uri.Scheme == "" || uri.Host == "" {
		return ""
	}
	uri.RawQuery = ""
	uri.Fragment = ""
	return uri.String()
}

func registrationEndpoint(serverMeta *ServerMetadata) string {
	if serverMeta == nil {
		return ""
	}
	if endpoint := strings.TrimSpace(serverMeta.Oidc.RegistrationEndpoint); endpoint != "" {
		return endpoint
	}
	return strings.TrimSpace(serverMeta.OAuth.RegistrationEndpoint)
}

func interoperabilityIssuerCandidates(resource string) []string {
	uri, err := url.Parse(strings.TrimSpace(resource))
	if err != nil || uri.Scheme == "" || uri.Host == "" {
		return nil
	}
	host := strings.ToLower(uri.Hostname())
	result := make([]string, 0, 1)
	if host == "atlassian.com" || strings.HasSuffix(host, ".atlassian.com") {
		result = append(result, (&url.URL{Scheme: uri.Scheme, Host: "auth.atlassian.com"}).String())
	}
	return compactIssuerCandidates(result)
}

func collectIssuerCandidates(groups ...[]string) []string {
	result := make([]string, 0)
	seen := map[string]struct{}{}
	for _, group := range groups {
		for _, issuer := range group {
			issuer = strings.TrimSpace(issuer)
			if issuer == "" {
				continue
			}
			if _, ok := seen[issuer]; ok {
				continue
			}
			seen[issuer] = struct{}{}
			result = append(result, issuer)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func compactIssuerCandidates(values []string) []string {
	return collectIssuerCandidates(values)
}

// resourceMetadataCandidates derives protected-resource metadata URLs from a resource URL.
func resourceMetadataCandidates(resource string) []string {
	return progressiveMetadataCandidates(resource, oidc.ProtectedResourcePath)
}

func progressiveMetadataCandidates(raw, wellKnownPath string) []string {
	var result []string

	uri, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || uri.Scheme == "" || uri.Host == "" {
		return nil
	}
	uri.RawQuery = ""
	uri.Fragment = ""

	parts := []string{}
	if path := strings.Trim(uri.EscapedPath(), "/"); path != "" {
		parts = strings.Split(path, "/")
	}

	for {
		path, err := url.JoinPath("/", append([]string{wellKnownPath}, parts...)...)
		if err != nil {
			break
		}

		uri.Path = path
		uri.RawPath = ""
		result = append(result, uri.String())

		if len(parts) == 0 {
			break
		}
		parts = parts[:len(parts)-1]
	}

	return result
}

// oidcMetadataCandidates derives OIDC discovery document URLs from an issuer URL.
func oidcMetadataCandidates(issuer string) []string {
	return metadataCandidates(issuer, oidc.ConfigPath, oidc.ConfigURL(issuer))
}

// oauthMetadataCandidates derives OAuth metadata URLs from an issuer URL.
func oauthMetadataCandidates(issuer string) []string {
	return metadataCandidates(issuer, oidc.OAuthConfigPath, oidc.OAuthConfigURL(issuer))
}

func metadataCandidates(raw, wellKnownPath, compatibility string) []string {
	var result []string
	seen := map[string]struct{}{}
	appendCandidate := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}

	// Prefer the canonical issuer-specific well-known URL first. For issuers with
	// a path component like http://host/api this resolves to
	// http://host/api/.well-known/openid-configuration, which avoids probing a
	// series of less likely fallback candidates before the correct endpoint.
	if compatibility := strings.TrimSpace(compatibility); compatibility != "" {
		appendCandidate(compatibility)
	}

	uri, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || uri.Scheme == "" || uri.Host == "" {
		return nil
	}
	uri.RawQuery = ""
	uri.Fragment = ""

	path := strings.TrimRight(uri.EscapedPath(), "/")
	if path != "" {
		uri.Path = "/" + wellKnownPath + path
		uri.RawPath = ""
		appendCandidate(uri.String())
	}

	root := &url.URL{Scheme: uri.Scheme, Host: uri.Host, Path: "/" + wellKnownPath}
	appendCandidate(root.String())

	return result
}

// DiscoverFromIssuer loads authorization server metadata from an issuer URL.
func (c *Client) discoverFromIssuer(ctx context.Context, issuer string) (*ServerMetadata, error) {
	meta := ServerMetadata{
		Issuer: strings.TrimSpace(issuer),
	}

	// Prefer OIDC discovery when available; it already carries the shared base
	// configuration fields used by the auth client flows.
	for _, endpoint := range oidcMetadataCandidates(meta.Issuer) {
		if err := c.DoWithContext(ctx, nil, &meta.Oidc, client.OptReqEndpoint(endpoint)); err == nil {
			return types.Ptr(meta), nil
		}
	}

	// Fall back to OAuth authorization-server metadata when no OIDC document is available.
	for _, endpoint := range oauthMetadataCandidates(meta.Issuer) {
		if err := c.DoWithContext(ctx, nil, &meta.OAuth, client.OptReqEndpoint(endpoint)); err == nil {
			return types.Ptr(meta), nil
		}
	}

	return nil, fmt.Errorf("fetch auth server metadata for %q: no valid OIDC or OAuth configuration found", meta.Issuer)
}
