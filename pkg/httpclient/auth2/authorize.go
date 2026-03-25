package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	// Packages
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
)

// AuthorizationCodeFlow creates an authorization-code flow from discovered metadata.
func (d *ProtectedResourceDiscovery) AuthorizationCodeFlow(clientID, redirectURL string, scopes ...string) (*oidc.AuthorizationCodeFlow, error) {
	clientID = strings.TrimSpace(clientID)
	redirectURL = strings.TrimSpace(redirectURL)
	if clientID == "" {
		return nil, fmt.Errorf("client ID is required")
	}
	if redirectURL == "" {
		return nil, fmt.Errorf("redirect URL is required")
	}
	server, err := d.authorizationServerForFlow()
	if err != nil {
		return nil, err
	}
	config, methods, err := server.authorizationCodeConfig()
	if err != nil {
		return nil, err
	}
	state, err := randomFlowToken(32)
	if err != nil {
		return nil, err
	}
	nonce, err := randomFlowToken(32)
	if err != nil {
		return nil, err
	}
	flow := &oidc.AuthorizationCodeFlow{
		Issuer:                strings.TrimSpace(config.Issuer),
		AuthorizationEndpoint: strings.TrimSpace(config.AuthorizationEndpoint),
		TokenEndpoint:         strings.TrimSpace(config.TokenEndpoint),
		ClientID:              clientID,
		RedirectURL:           redirectURL,
		ResponseType:          oidc.ResponseTypeCode,
		Scopes:                authorizationScopes(server, scopes...),
		State:                 state,
		Nonce:                 nonce,
	}
	if method := oidc.PreferredCodeChallengeMethod(methods); method != "" {
		verifier, challenge, err := oidc.NewCodeChallenge(method)
		if err != nil {
			return nil, err
		}
		flow.CodeChallengeMethod = method
		flow.CodeVerifier = verifier
		flow.CodeChallenge = challenge
	}
	uri, err := flow.URL()
	if err != nil {
		return nil, err
	}
	flow.AuthorizationURL = uri
	return flow, nil
}

// RegisterClientWithContext registers a public client with the preferred auth server.
func (d *ProtectedResourceDiscovery) RegisterClientWithContext(ctx context.Context, authClient *AuthClient, redirectURL string) (*ClientRegistrationResponse, error) {
	server, err := d.authorizationServerForRegistration()
	if err != nil {
		return nil, err
	}
	return server.OAuth.RegisterClientWithContext(ctx, authClient, &ClientRegistrationRequest{
		RedirectURIs: []string{strings.TrimSpace(redirectURL)},
	})
}

func (d *ProtectedResourceDiscovery) authorizationServerForFlow() (*AuthorizationServerInfo, error) {
	if d == nil || len(d.AuthorizationServers) == 0 {
		return nil, fmt.Errorf("authorization server metadata is required")
	}
	for index := range d.AuthorizationServers {
		server := &d.AuthorizationServers[index]
		if hasAuthorizationEndpoint(server) {
			return server, nil
		}
	}
	return &d.AuthorizationServers[0], nil
}

func (d *ProtectedResourceDiscovery) authorizationServerForRegistration() (*AuthorizationServerInfo, error) {
	if d == nil || len(d.AuthorizationServers) == 0 {
		return nil, fmt.Errorf("authorization server metadata is required")
	}
	for index := range d.AuthorizationServers {
		server := &d.AuthorizationServers[index]
		if server.OAuth != nil && strings.TrimSpace(server.OAuth.RegistrationEndpoint) != "" {
			return server, nil
		}
	}
	return nil, fmt.Errorf("no registration endpoint is advertised")
}

func (server *AuthorizationServerInfo) authorizationCodeConfig() (oidc.Configuration, []string, error) {
	if server == nil {
		return oidc.Configuration{}, nil, fmt.Errorf("authorization server is required")
	}
	config := oidc.Configuration{Issuer: strings.TrimSpace(server.Issuer)}
	methods := []string(nil)
	if server.OIDC != nil {
		config = *server.OIDC
		methods = append(methods, server.OIDC.CodeChallengeMethods...)
	}
	if server.OAuth != nil {
		if strings.TrimSpace(config.Issuer) == "" {
			config.Issuer = strings.TrimSpace(server.OAuth.Issuer)
		}
		if strings.TrimSpace(config.AuthorizationEndpoint) == "" {
			config.AuthorizationEndpoint = strings.TrimSpace(server.OAuth.AuthorizationEndpoint)
		}
		if strings.TrimSpace(config.TokenEndpoint) == "" {
			config.TokenEndpoint = strings.TrimSpace(server.OAuth.TokenEndpoint)
		}
		if len(methods) == 0 {
			methods = append(methods, server.OAuth.CodeChallengeMethodsSupported...)
		}
	}
	if strings.TrimSpace(config.Issuer) == "" {
		config.Issuer = strings.TrimSpace(server.Issuer)
	}
	if strings.TrimSpace(config.AuthorizationEndpoint) == "" {
		return oidc.Configuration{}, nil, fmt.Errorf("authorization endpoint is required")
	}
	return config, compactStrings(methods), nil
}

func authorizationScopes(server *AuthorizationServerInfo, scopes ...string) []string {
	if scopes = compactStrings(scopes); len(scopes) > 0 {
		return scopes
	}
	if server != nil && server.OIDC != nil {
		return oidc.AuthorizationScopes(*server.OIDC)
	}
	return nil
}

func hasAuthorizationEndpoint(server *AuthorizationServerInfo) bool {
	if server == nil {
		return false
	}
	if server.OIDC != nil && strings.TrimSpace(server.OIDC.AuthorizationEndpoint) != "" {
		return true
	}
	if server.OAuth != nil && strings.TrimSpace(server.OAuth.AuthorizationEndpoint) != "" {
		return true
	}
	return false
}

func randomFlowToken(size int) (string, error) {
	if size <= 0 {
		return "", fmt.Errorf("token size must be greater than zero")
	}
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
