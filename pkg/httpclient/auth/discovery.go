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

	if compatibility := strings.TrimSpace(compatibility); compatibility != "" {
		appendCandidate(compatibility)
	}

	return result
}

// DiscoverFromIssuer loads authorization server metadata from an issuer URL.
func (c *Client) discoverFromIssuer(ctx context.Context, issuer string) (*ServerMetadata, error) {
	var found bool
	meta := ServerMetadata{
		Issuer: strings.TrimSpace(issuer),
	}

	// Discover OIDC and OAuth metadata from the issuer URL, trying multiple candidates for compatibility with different server implementations
	for _, endpoint := range oidcMetadataCandidates(meta.Issuer) {
		if err := c.DoWithContext(ctx, nil, &meta.Oidc, client.OptReqEndpoint(endpoint)); err == nil {
			found = true
			break
		}
	}

	for _, endpoint := range oauthMetadataCandidates(meta.Issuer) {
		if err := c.DoWithContext(ctx, nil, &meta.OAuth, client.OptReqEndpoint(endpoint)); err == nil {
			found = true
			break
		}
	}

	// If some valid metadata was found, return it, otherwise return an error
	if found {
		return types.Ptr(meta), nil
	} else {
		return nil, fmt.Errorf("fetch auth server metadata for %q: no valid OIDC or OAuth configuration found", meta.Issuer)
	}
}
