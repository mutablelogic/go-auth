package auth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	// Packages
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	client "github.com/mutablelogic/go-client"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - AUTH DISCOVERY

// DiscoverWithContext resolves auth metadata from an auth challenge.
func (c *AuthClient) DiscoverWithContext(ctx context.Context, err error) (*ProtectedResourceDiscovery, error) {
	authErr, ok := authErrorFrom(err)
	if !ok {
		return nil, err
	}

	resourceMetadata := strings.TrimSpace(authErr.Get("resource_metadata"))
	if resourceMetadata == "" {
		return c.discoverWithoutResourceMetadata(ctx, authErr)
	}
	return c.discoverFromResourceMetadata(ctx, authErr, resourceMetadata, false)
}

// DiscoverIssuerWithContext resolves auth server metadata directly from an issuer URL.
func (c *AuthClient) DiscoverIssuerWithContext(ctx context.Context, issuer string) (*ProtectedResourceDiscovery, error) {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		issuer = strings.TrimSpace(c.Endpoint)
	}
	if issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}
	info, err := c.discoverAuthorizationServer(ctx, issuer, issuer)
	if err != nil {
		return nil, err
	}
	return &ProtectedResourceDiscovery{
		AuthorizationServers: []AuthorizationServerInfo{*info},
		Warnings:             append([]string(nil), info.Warnings...),
	}, nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

type authServerCandidate struct {
	issuer  string
	warning string
}

// authErrorFrom unwraps an AuthError from a request failure.
func authErrorFrom(err error) (*AuthError, bool) {
	var authErr *AuthError
	if !errors.As(err, &authErr) || authErr == nil {
		return nil, false
	}
	return authErr, true
}

// discoverWithoutResourceMetadata falls back when no resource_metadata hint is present.
func (c *AuthClient) discoverWithoutResourceMetadata(ctx context.Context, authErr *AuthError) (*ProtectedResourceDiscovery, error) {
	var resource oidc.ProtectedResourceMetadata
	resourceMetadata, metadataErr := c.discoverResourceMetadata(ctx, &resource)
	if metadataErr == nil {
		return c.discoverFromLoadedResourceMetadata(ctx, authErr, resourceMetadata, &resource, true)
	}

	for _, candidate := range c.authServerCandidates(authErr) {
		result, ok := c.discoverFromIssuer(ctx, authErr, candidate)
		if ok {
			return result, nil
		}
	}

	return nil, fmt.Errorf("discover resource metadata: %w", metadataErr)
}

// discoverFromResourceMetadata fetches discovery from an explicit metadata endpoint.
func (c *AuthClient) discoverFromResourceMetadata(ctx context.Context, authErr *AuthError, endpoint string, derived bool) (*ProtectedResourceDiscovery, error) {
	var resource oidc.ProtectedResourceMetadata
	if err := c.getJSONWithContext(ctx, endpoint, &resource); err != nil {
		return nil, fmt.Errorf("fetch resource metadata: %w", err)
	}
	return c.discoverFromLoadedResourceMetadata(ctx, authErr, endpoint, &resource, derived)
}

// discoverFromLoadedResourceMetadata expands loaded resource metadata into auth server details.
func (c *AuthClient) discoverFromLoadedResourceMetadata(ctx context.Context, authErr *AuthError, endpoint string, resource *oidc.ProtectedResourceMetadata, derived bool) (*ProtectedResourceDiscovery, error) {
	result := &ProtectedResourceDiscovery{
		Challenge:        authErr,
		ResourceMetadata: resource,
	}
	if derived {
		result.Warnings = append(result.Warnings, fmt.Sprintf("derived resource_metadata from protected resource URL: %s", endpoint))
	}
	if resource == nil {
		return result, nil
	}
	for _, issuer := range resource.AuthorizationServers {
		issuer = strings.TrimSpace(issuer)
		if issuer == "" {
			continue
		}
		info, err := c.discoverAuthorizationServer(ctx, issuer, resource.Resource)
		if err != nil {
			return nil, err
		}
		result.AuthorizationServers = append(result.AuthorizationServers, *info)
		result.Warnings = append(result.Warnings, info.Warnings...)
	}
	return result, nil
}

// authServerCandidates derives possible authorization server issuers from a challenge.
func (c *AuthClient) authServerCandidates(authErr *AuthError) []authServerCandidate {
	result := make([]authServerCandidate, 0, 3)
	for _, issuer := range authorizationURIIssuerCandidates(authErr) {
		result = append(result, authServerCandidate{
			issuer:  issuer,
			warning: fmt.Sprintf("protected resource metadata not found for %q; inferred authorization server from authorization_uri %q", c.Endpoint, issuer),
		})
	}
	if issuer := absoluteRealmURL(authErr); issuer != "" {
		result = append(result, authServerCandidate{
			issuer:  issuer,
			warning: fmt.Sprintf("protected resource metadata not found for %q; inferred authorization server from Bearer realm %q", c.Endpoint, issuer),
		})
	}
	if issuer := originURL(c.Endpoint); issuer != "" {
		result = append(result, authServerCandidate{
			issuer:  issuer,
			warning: fmt.Sprintf("protected resource metadata not found for %q; inferred authorization server from resource origin %q", c.Endpoint, issuer),
		})
	}
	return result
}

// discoverFromIssuer loads authorization server metadata from a candidate issuer.
func (c *AuthClient) discoverFromIssuer(ctx context.Context, authErr *AuthError, candidate authServerCandidate) (*ProtectedResourceDiscovery, bool) {
	info, err := c.discoverAuthorizationServer(ctx, candidate.issuer, c.Endpoint)
	if err != nil {
		return nil, false
	}
	return &ProtectedResourceDiscovery{
		Challenge:            authErr,
		AuthorizationServers: []AuthorizationServerInfo{*info},
		Warnings:             append([]string{candidate.warning}, info.Warnings...),
	}, true
}

// getJSONWithContext fetches JSON from an absolute endpoint into v.
func (c *AuthClient) getJSONWithContext(ctx context.Context, endpoint string, v any) error {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return fmt.Errorf("endpoint is required")
	}
	return c.DoWithContext(ctx, nil, v, client.OptReqEndpoint(endpoint))
}

// discoverResourceMetadata probes well-known protected-resource metadata endpoints.
func (c *AuthClient) discoverResourceMetadata(ctx context.Context, metadata *oidc.ProtectedResourceMetadata) (string, error) {
	if metadata == nil {
		return "", fmt.Errorf("metadata is required")
	}
	for _, endpoint := range resourceMetadataCandidates(c.Endpoint) {
		if err := c.getJSONWithContext(ctx, endpoint, metadata); err == nil {
			return endpoint, nil
		} else if !isHTTPStatus(err, httpresponse.ErrNotFound) && !isHTTPStatus(err, httpresponse.ErrNotAuthorized) {
			return "", fmt.Errorf("fetch resource metadata from %q: %w", endpoint, err)
		}
	}
	return "", fmt.Errorf("no protected resource metadata found for %q", c.Endpoint)
}

// discoverAuthorizationServer loads OIDC and OAuth metadata for an issuer.
func (c *AuthClient) discoverAuthorizationServer(ctx context.Context, issuer, resource string) (*AuthorizationServerInfo, error) {
	result := &AuthorizationServerInfo{Issuer: issuer}

	var discovery oidc.Configuration
	oidcErr := c.getJSONWithContext(ctx, oidc.ConfigURL(issuer), &discovery)
	if oidcErr == nil {
		result.OIDC = &discovery
	}

	var oauth OAuthAuthorizationServer
	oauthErr := c.getJSONWithContext(ctx, oauthAuthorizationServerURL(issuer), &oauth)
	if oauthErr == nil {
		result.OAuth = &oauth
	}

	if oidcErr != nil && oauthErr != nil {
		return nil, fmt.Errorf("fetch auth server metadata for %q: oidc=%v; oauth=%v", issuer, oidcErr, oauthErr)
	}

	result.Warnings = append(result.Warnings, discoveryWarnings(issuer, &discovery, result.OAuth)...)

	if shouldProbeProviderHint(resource, issuer, result) {
		for _, endpoint := range providerHintCandidates(issuer) {
			var providers oidc.PublicClientConfigurations
			if err := c.getJSONWithContext(ctx, endpoint, &providers); err == nil {
				result.ProviderHint = providers
				break
			} else if !isHTTPStatus(err, httpresponse.ErrNotFound) && !isHTTPStatus(err, httpresponse.ErrNotAuthorized) {
				return nil, fmt.Errorf("fetch auth config from %q: %w", endpoint, err)
			}
		}
	}

	return result, nil
}

// discoveryWarnings reports missing auth server metadata and endpoints.
func discoveryWarnings(issuer string, discovery *oidc.Configuration, oauth *OAuthAuthorizationServer) []string {
	warnings := make([]string, 0, 4)
	if discovery == nil {
		warnings = append(warnings, fmt.Sprintf("issuer %q does not publish OpenID configuration", issuer))
	}
	if oauth == nil {
		warnings = append(warnings, fmt.Sprintf("issuer %q does not publish OAuth authorization server metadata", issuer))
	}
	authorizationEndpoint := ""
	tokenEndpoint := ""
	if discovery != nil {
		authorizationEndpoint = strings.TrimSpace(discovery.AuthorizationEndpoint)
		tokenEndpoint = strings.TrimSpace(discovery.TokenEndpoint)
	}
	if oauth != nil {
		if authorizationEndpoint == "" {
			authorizationEndpoint = strings.TrimSpace(oauth.AuthorizationEndpoint)
		}
		if tokenEndpoint == "" {
			tokenEndpoint = strings.TrimSpace(oauth.TokenEndpoint)
		}
	}
	if authorizationEndpoint == "" {
		warnings = append(warnings, fmt.Sprintf("issuer %q does not advertise authorization_endpoint", issuer))
	}
	if tokenEndpoint == "" {
		warnings = append(warnings, fmt.Sprintf("issuer %q does not advertise token_endpoint", issuer))
	}
	return warnings
}

// isHTTPStatus reports whether err unwraps to the supplied HTTP error code.
func isHTTPStatus(err error, code httpresponse.Err) bool {
	var status httpresponse.Err
	return errors.As(err, &status) && status == code
}

// mustJoinURL joins a path onto a base URL, falling back to base on error.
func mustJoinURL(base, path string) string {
	uri, err := url.JoinPath(base, path)
	if err != nil {
		return base
	}
	return uri
}

// oauthAuthorizationServerURL returns the OAuth metadata URL for an issuer.
func oauthAuthorizationServerURL(issuer string) string {
	uri, err := url.JoinPath(issuer, ".well-known/oauth-authorization-server")
	if err != nil {
		return issuer
	}
	return uri
}

// resourceMetadataCandidates derives protected-resource metadata URLs from a resource URL.
func resourceMetadataCandidates(raw string) []string {
	uri, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || uri.Scheme == "" || uri.Host == "" {
		return nil
	}
	seen := map[string]struct{}{}
	result := make([]string, 0, 2)
	add := func(value string) {
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
	path := strings.TrimSpace(uri.EscapedPath())
	base := &url.URL{Scheme: uri.Scheme, Host: uri.Host}
	if path != "" && path != "/" {
		base.Path = "/" + oidc.ProtectedResourcePath + path
		add(base.String())
	}
	base.Path = "/" + oidc.ProtectedResourcePath
	add(base.String())
	return result
}

// providerHintCandidates returns go-auth-specific provider hint endpoints for an issuer.
func providerHintCandidates(issuer string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, 2)
	for _, endpoint := range []string{mustJoinURL(issuer, "auth/config"), rootAuthConfigURL(issuer)} {
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			continue
		}
		if _, ok := seen[endpoint]; ok {
			continue
		}
		seen[endpoint] = struct{}{}
		result = append(result, endpoint)
	}
	return result
}

// rootAuthConfigURL rewrites an issuer to the host-root auth config endpoint.
func rootAuthConfigURL(issuer string) string {
	uri, err := url.Parse(strings.TrimSpace(issuer))
	if err != nil {
		return ""
	}
	uri.Path = "/auth/config"
	uri.RawPath = ""
	uri.RawQuery = ""
	uri.Fragment = ""
	return uri.String()
}

// shouldProbeProviderHint reports whether provider hints are worth probing.
func shouldProbeProviderHint(resource, issuer string, info *AuthorizationServerInfo) bool {
	if !sameOrigin(resource, issuer) || info == nil {
		return false
	}
	if info.OIDC != nil {
		if hasAuthPrefix(info.OIDC.TokenEndpoint) || hasAuthPrefix(info.OIDC.UserInfoEndpoint) {
			return true
		}
	}
	return false
}

// hasAuthPrefix reports whether a URL path contains the local auth prefix.
func hasAuthPrefix(raw string) bool {
	uri, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	return strings.Contains(uri.Path, "/auth/")
}

// sameOrigin reports whether two URLs share scheme and host.
func sameOrigin(left, right string) bool {
	leftURL, err := url.Parse(strings.TrimSpace(left))
	if err != nil {
		return false
	}
	rightURL, err := url.Parse(strings.TrimSpace(right))
	if err != nil {
		return false
	}
	return strings.EqualFold(leftURL.Scheme, rightURL.Scheme) && strings.EqualFold(leftURL.Host, rightURL.Host)
}

// originURL returns the scheme and host of a URL.
func originURL(raw string) string {
	uri, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || uri.Scheme == "" || uri.Host == "" {
		return ""
	}
	return (&url.URL{Scheme: uri.Scheme, Host: uri.Host}).String()
}

// absoluteRealmURL returns the realm when it is an absolute URL.
func absoluteRealmURL(authErr *AuthError) string {
	if authErr == nil {
		return ""
	}
	realm := strings.TrimSpace(authErr.Get("realm"))
	uri, err := url.Parse(realm)
	if err != nil || uri.Scheme == "" || uri.Host == "" {
		return ""
	}
	return uri.String()
}

// authorizationURIIssuerCandidates derives issuer candidates from authorization_uri.
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
	for _, suffix := range []string{"/oauth2/v2.0/authorize", "/oauth2/authorize", "/authorize"} {
		if strings.HasSuffix(path, suffix) {
			path = strings.TrimSuffix(path, suffix)
			break
		}
	}
	if path == "" {
		return []string{(&url.URL{Scheme: uri.Scheme, Host: uri.Host}).String()}
	}
	return []string{(&url.URL{Scheme: uri.Scheme, Host: uri.Host, Path: path}).String()}
}
