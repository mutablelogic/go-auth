package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

const (
	ResponseTypeCode         = "code"
	CodeChallengeMethodPlain = "plain"
	CodeChallengeMethodS256  = "S256"
	randomTokenBytes         = 32
)

var defaultAuthorizationScopes = []string{ScopeOpenID, ScopeEmail, ScopeProfile}

// AuthorizationCodeFlow contains the generated state required to start an
// interactive OAuth2/OIDC authorization code flow with optional PKCE.
type AuthorizationCodeFlow struct {
	Issuer                string   `json:"issuer,omitempty"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	AuthorizationURL      string   `json:"authorization_url"`
	TokenEndpoint         string   `json:"token_endpoint,omitempty"`
	ClientID              string   `json:"client_id"`
	RedirectURL           string   `json:"redirect_url"`
	ResponseType          string   `json:"response_type"`
	Scopes                []string `json:"scopes,omitempty"`
	State                 string   `json:"state"`
	Nonce                 string   `json:"nonce,omitempty"`
	CodeChallenge         string   `json:"code_challenge,omitempty"`
	CodeChallengeMethod   string   `json:"code_challenge_method,omitempty"`
	CodeVerifier          string   `json:"code_verifier,omitempty"`
}

// NewAuthorizationCodeFlow generates state, nonce, and PKCE data needed to
// begin an OIDC authorization code flow using the supplied discovery document.
func NewAuthorizationCodeFlow(config Configuration, clientID, redirectURL string, scopes ...string) (*AuthorizationCodeFlow, error) {
	clientID = strings.TrimSpace(clientID)
	redirectURL = strings.TrimSpace(redirectURL)
	if strings.TrimSpace(config.AuthorizationEndpoint) == "" {
		return nil, fmt.Errorf("authorization endpoint is required")
	}
	if clientID == "" {
		return nil, fmt.Errorf("client ID is required")
	}
	if redirectURL == "" {
		return nil, fmt.Errorf("redirect URL is required")
	}
	scopes = AuthorizationScopes(config, scopes...)
	state, err := randomToken(randomTokenBytes)
	if err != nil {
		return nil, err
	}
	nonce, err := randomToken(randomTokenBytes)
	if err != nil {
		return nil, err
	}
	flow := &AuthorizationCodeFlow{
		Issuer:                strings.TrimSpace(config.Issuer),
		AuthorizationEndpoint: strings.TrimSpace(config.AuthorizationEndpoint),
		TokenEndpoint:         strings.TrimSpace(config.TokenEndpoint),
		ClientID:              clientID,
		RedirectURL:           redirectURL,
		ResponseType:          ResponseTypeCode,
		Scopes:                scopes,
		State:                 state,
		Nonce:                 nonce,
	}
	if method := PreferredCodeChallengeMethod(config.CodeChallengeMethods); method != "" {
		verifier, challenge, err := NewCodeChallenge(method)
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

// AuthorizationScopes returns the caller-supplied scopes, or the preferred
// default OIDC scopes filtered to those advertised by discovery when present.
func AuthorizationScopes(config Configuration, scopes ...string) []string {
	if len(scopes) > 0 {
		return append([]string(nil), scopes...)
	}
	if len(config.ScopesSupported) == 0 {
		return append([]string(nil), defaultAuthorizationScopes...)
	}
	supported := make(map[string]struct{}, len(config.ScopesSupported))
	for _, scope := range config.ScopesSupported {
		scope = strings.TrimSpace(scope)
		if scope != "" {
			supported[scope] = struct{}{}
		}
	}
	selected := make([]string, 0, len(defaultAuthorizationScopes))
	for _, scope := range defaultAuthorizationScopes {
		if _, ok := supported[scope]; ok {
			selected = append(selected, scope)
		}
	}
	if len(selected) > 0 {
		return selected
	}
	return append([]string(nil), defaultAuthorizationScopes...)
}

// URL returns the authorization URL for the flow.
func (flow AuthorizationCodeFlow) URL() (string, error) {
	endpoint := strings.TrimSpace(flow.AuthorizationEndpoint)
	if endpoint == "" {
		return "", fmt.Errorf("authorization endpoint is required")
	}
	if strings.TrimSpace(flow.ClientID) == "" {
		return "", fmt.Errorf("client ID is required")
	}
	if strings.TrimSpace(flow.RedirectURL) == "" {
		return "", fmt.Errorf("redirect URL is required")
	}
	if strings.TrimSpace(flow.State) == "" {
		return "", fmt.Errorf("state is required")
	}
	responseType := strings.TrimSpace(flow.ResponseType)
	if responseType == "" {
		responseType = ResponseTypeCode
	}
	values := url.Values{}
	values.Set("client_id", flow.ClientID)
	values.Set("redirect_uri", flow.RedirectURL)
	values.Set("response_type", responseType)
	values.Set("state", flow.State)
	if len(flow.Scopes) > 0 {
		values.Set("scope", strings.Join(flow.Scopes, " "))
	}
	if nonce := strings.TrimSpace(flow.Nonce); nonce != "" {
		values.Set("nonce", nonce)
	}
	if challenge := strings.TrimSpace(flow.CodeChallenge); challenge != "" {
		values.Set("code_challenge", challenge)
	}
	if method := strings.TrimSpace(flow.CodeChallengeMethod); method != "" {
		values.Set("code_challenge_method", method)
	}
	uri, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	uri.RawQuery = values.Encode()
	return uri.String(), nil
}

// PreferredCodeChallengeMethod chooses the strongest supported PKCE method.
func PreferredCodeChallengeMethod(methods []string) string {
	var plain bool
	for _, method := range methods {
		switch strings.TrimSpace(method) {
		case CodeChallengeMethodS256:
			return CodeChallengeMethodS256
		case CodeChallengeMethodPlain:
			plain = true
		}
	}
	if plain {
		return CodeChallengeMethodPlain
	}
	return ""
}

// NewCodeChallenge generates a code verifier and derived code challenge using
// the requested PKCE method.
func NewCodeChallenge(method string) (string, string, error) {
	method = strings.TrimSpace(method)
	if method == "" {
		method = CodeChallengeMethodS256
	}
	verifier, err := randomToken(48)
	if err != nil {
		return "", "", err
	}
	switch method {
	case CodeChallengeMethodPlain:
		return verifier, verifier, nil
	case CodeChallengeMethodS256:
		sum := sha256.Sum256([]byte(verifier))
		return verifier, base64.RawURLEncoding.EncodeToString(sum[:]), nil
	default:
		return "", "", fmt.Errorf("unsupported code challenge method %q", method)
	}
}

func randomToken(size int) (string, error) {
	if size <= 0 {
		return "", fmt.Errorf("token size must be greater than zero")
	}
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
