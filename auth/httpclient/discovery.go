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

package httpclient

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	// Packages
	oidc "github.com/mutablelogic/go-auth/auth/oidc"
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
// PUBLIC METHODS

// DiscoverWithError resolves auth metadata from an auth challenge.
func (c *Client) DiscoverWithError(ctx context.Context, err error) (*Config, error) {
	authErr := AsAuthError(err)
	if authErr == nil {
		return nil, err
	}

	config := new(Config)
	seen := map[string]struct{}{}

	// Attempt discovery using resource_metadata hint, if present.
	if endpoint := strings.TrimSpace(authErr.Get("resource_metadata")); endpoint != "" {
		var resource oidc.ProtectedResourceMetadata
		if err := c.DoWithContext(ctx, nil, &resource, client.OptReqEndpoint(endpoint)); err != nil {
			return nil, fmt.Errorf("fetch resource metadata from %q: %w", endpoint, err)
		}
		resourceConfig := &Config{ProtectedResourceMetadata: resource}
		c.appendDiscoveredServers(ctx, resourceConfig, map[string]struct{}{}, resource.AuthorizationServers...)
		mergeDiscoveredConfig(config, seen, resourceConfig)
	}

	c.appendDiscoveredServers(ctx, config, seen, authServerCandidates(authErr)...)
	if len(config.AuthorizationServers) == 0 {
		return nil, fmt.Errorf("authorization server metadata is required")
	}
	return config, nil
}

// Discover resolves auth server metadata directly from an issuer URL.
func (c *Client) Discover(ctx context.Context, issuer string) (*Config, error) {
	config := new(Config)
	seen := map[string]struct{}{}
	for _, endpoint := range progressiveMetadataCandidates(issuer, oidc.ProtectedResourcePath) {
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
	c.appendDiscoveredServers(ctx, config, seen, config.ProtectedResourceMetadata.AuthorizationServers...)
	if len(config.AuthorizationServers) == 0 {
		c.appendDiscoveredServers(ctx, config, seen, issuer)
	}
	if len(config.AuthorizationServers) == 0 {
		c.appendDiscoveredServers(ctx, config, seen, interoperabilityIssuerCandidates(issuer)...)
	}
	return config, nil
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

// AuthorizationServerForFlow selects a discovered authorization server that
// advertises an authorization endpoint.
func (c *Config) AuthorizationServerForFlow() (*ServerMetadata, error) {
	if c == nil || len(c.AuthorizationServers) == 0 {
		return nil, fmt.Errorf("authorization server metadata is required")
	}
	for index := range c.AuthorizationServers {
		serverMeta := &c.AuthorizationServers[index]
		if _, ok := serverMeta.authorizationCodeBaseConfig(); ok {
			return serverMeta, nil
		}
	}
	return nil, fmt.Errorf("no authorization code flow is advertised")
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
	if config, ok := serverMeta.authorizationCodeBaseConfig(); ok {
		return config, nil
	}
	return oidc.BaseConfiguration{}, fmt.Errorf("no authorization code flow is advertised")
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func hasAuthorizationCodeFlow(config oidc.BaseConfiguration) bool {
	return strings.TrimSpace(config.AuthorizationEndpoint) != "" && strings.TrimSpace(config.TokenEndpoint) != ""
}

func buildAuthorizationCodeConfig(issuer string, config oidc.BaseConfiguration, authMethods []string, nonceSupported bool) (oidc.BaseConfiguration, bool) {
	if !hasAuthorizationCodeFlow(config) {
		return oidc.BaseConfiguration{}, false
	}
	if strings.TrimSpace(config.Issuer) == "" {
		config.Issuer = strings.TrimSpace(issuer)
	}
	config.TokenEndpointAuthMethods = compactStrings(authMethods)
	config.NonceSupported = nonceSupported
	return config, true
}

func (serverMeta *ServerMetadata) authorizationCodeBaseConfig() (oidc.BaseConfiguration, bool) {
	if serverMeta == nil {
		return oidc.BaseConfiguration{}, false
	}
	if config, ok := buildAuthorizationCodeConfig(serverMeta.Issuer, serverMeta.Oidc.BaseConfiguration, serverMeta.Oidc.TokenEndpointAuthMethodsSupported, true); ok {
		return config, true
	}
	if config, ok := buildAuthorizationCodeConfig(serverMeta.Issuer, serverMeta.OAuth.BaseConfiguration, serverMeta.OAuth.TokenEndpointAuthMethodsSupported, false); ok {
		return config, true
	}
	return oidc.BaseConfiguration{}, false
}

func mergeDiscoveredConfig(dst *Config, seen map[string]struct{}, src *Config) {
	if dst == nil || src == nil {
		return
	}
	if strings.TrimSpace(src.ProtectedResourceMetadata.Resource) != "" || len(src.ProtectedResourceMetadata.AuthorizationServers) > 0 {
		dst.ProtectedResourceMetadata = src.ProtectedResourceMetadata
	}
	dst.AuthorizationServers = append(dst.AuthorizationServers, src.AuthorizationServers...)
	if seen == nil {
		return
	}
	for _, serverMeta := range src.AuthorizationServers {
		issuer := strings.TrimSpace(serverMeta.Issuer)
		if issuer == "" {
			continue
		}
		seen[issuer] = struct{}{}
	}
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

func authServerCandidates(authErr *AuthError) []string {
	result := make([]string, 0, 3)
	for _, key := range []string{"issuer", "authorization_server", "authorization_server_uri"} {
		value := absoluteURL(authErr.Get(key))
		if value != "" {
			result = append(result, value)
		}
	}
	return collectIssuerCandidates(
		result,
		authorizationURIIssuerCandidates(authErr),
		[]string{absoluteURL(authErr.Get("realm"))},
	)
}

func authorizationURIIssuerCandidates(authErr *AuthError) []string {
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
	return collectIssuerCandidates(result)
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
		path, err := url.JoinPath("/", append(parts, wellKnownPath)...)
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
	var found bool

	for _, endpoint := range metadataCandidates(meta.Issuer, oidc.ConfigPath, oidc.ConfigURL(meta.Issuer)) {
		if err := c.DoWithContext(ctx, nil, &meta.Oidc, client.OptReqEndpoint(endpoint)); err == nil {
			found = true
			break
		}
	}
	if _, ok := meta.authorizationCodeBaseConfig(); ok {
		if issuer := strings.TrimSpace(meta.Oidc.Issuer); issuer != "" {
			meta.Issuer = issuer
		}
		return types.Ptr(meta), nil
	}

	for _, endpoint := range metadataCandidates(meta.Issuer, oidc.OAuthConfigPath, oidc.OAuthConfigURL(meta.Issuer)) {
		if err := c.DoWithContext(ctx, nil, &meta.OAuth, client.OptReqEndpoint(endpoint)); err == nil {
			found = true
			break
		}
	}
	if issuer := strings.TrimSpace(meta.Oidc.Issuer); issuer != "" {
		meta.Issuer = issuer
	} else if issuer := strings.TrimSpace(meta.OAuth.Issuer); issuer != "" {
		meta.Issuer = issuer
	}

	if _, ok := meta.authorizationCodeBaseConfig(); ok {
		return types.Ptr(meta), nil
	}
	if meta.applyLegacyAuthorizationCodeFallback() {
		return types.Ptr(meta), nil
	}
	if found {
		return nil, fmt.Errorf("fetch auth server metadata for %q: no authorization code flow is advertised", meta.Issuer)
	}

	return nil, fmt.Errorf("fetch auth server metadata for %q: no valid OIDC or OAuth configuration found", meta.Issuer)
}

func (serverMeta *ServerMetadata) applyLegacyAuthorizationCodeFallback() bool {
	if serverMeta == nil {
		return false
	}
	issuer := strings.TrimRight(strings.TrimSpace(serverMeta.Issuer), "/")
	uri, err := url.Parse(issuer)
	if err != nil || uri.Scheme == "" || uri.Host == "" {
		return false
	}
	if strings.EqualFold(uri.Hostname(), "github.com") && strings.TrimRight(uri.Path, "/") == "/login/oauth" {
		serverMeta.OAuth.BaseConfiguration = oidc.BaseConfiguration{
			Issuer:                   issuer,
			AuthorizationEndpoint:    issuer + "/authorize",
			TokenEndpoint:            issuer + "/access_token",
			TokenEndpointAuthMethods: []string{"client_secret_post"},
		}
		serverMeta.OAuth.TokenEndpointAuthMethodsSupported = []string{"client_secret_post"}
		return true
	}
	return false
}
