package google

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	// Packages
	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	providerpkg "github.com/djthorpe/go-auth/pkg/provider"
	schema "github.com/djthorpe/go-auth/schema"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
	oauth2 "golang.org/x/oauth2"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type Provider struct {
	clientID     string
	clientSecret string
	issuer       string
}

var _ providerpkg.Provider = (*Provider)(nil)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const key = "google"

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func New(clientID, clientSecret string) (*Provider, error) {
	return NewWithIssuer(clientID, clientSecret, oidc.GoogleIssuer)
}

func NewWithIssuer(clientID, clientSecret, issuer string) (*Provider, error) {
	clientID = strings.TrimSpace(clientID)
	clientSecret = strings.TrimSpace(clientSecret)
	issuer = strings.TrimSpace(issuer)
	if clientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if clientSecret == "" {
		return nil, fmt.Errorf("client_secret is required")
	}
	if issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}
	return &Provider{
		clientID:     clientID,
		clientSecret: clientSecret,
		issuer:       issuer,
	}, nil
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (p *Provider) Key() string {
	return key
}

func (p *Provider) PublicConfig() schema.PublicClientConfiguration {
	return schema.PublicClientConfiguration{
		Issuer:   p.issuer,
		ClientID: p.clientID,
	}
}

func (p *Provider) HTTPHandler() (http.HandlerFunc, *openapi.PathItem) {
	return nil, nil
}

func (p *Provider) BeginAuthorization(ctx context.Context, req providerpkg.AuthorizationRequest) (*providerpkg.AuthorizationResponse, error) {
	if p == nil {
		return nil, fmt.Errorf("provider is required")
	}
	if strings.TrimSpace(req.ClientID) == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if strings.TrimSpace(req.RedirectURL) == "" {
		return nil, fmt.Errorf("redirect_url is required")
	}
	if strings.TrimSpace(req.State) == "" {
		return nil, fmt.Errorf("state is required")
	}
	provider, err := coreoidc.NewProvider(ctx, p.issuer)
	if err != nil {
		return nil, err
	}
	oauthConfig := &oauth2.Config{
		ClientID:     p.clientID,
		ClientSecret: p.clientSecret,
		RedirectURL:  req.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       req.Scopes,
	}
	options := make([]oauth2.AuthCodeOption, 0, 4)
	if nonce := strings.TrimSpace(req.Nonce); nonce != "" {
		options = append(options, oauth2.SetAuthURLParam("nonce", nonce))
	}
	if challenge := strings.TrimSpace(req.CodeChallenge); challenge != "" {
		options = append(options, oauth2.SetAuthURLParam("code_challenge", challenge))
	}
	if method := strings.TrimSpace(req.CodeChallengeMethod); method != "" {
		options = append(options, oauth2.SetAuthURLParam("code_challenge_method", method))
	}
	if loginHint := strings.TrimSpace(req.LoginHint); loginHint != "" {
		options = append(options, oauth2.SetAuthURLParam("login_hint", loginHint))
	}
	return &providerpkg.AuthorizationResponse{RedirectURL: oauthConfig.AuthCodeURL(req.State, options...)}, nil
}

func (p *Provider) ExchangeAuthorizationCode(ctx context.Context, req providerpkg.ExchangeRequest) (*schema.IdentityInsert, error) {
	if p == nil {
		return nil, fmt.Errorf("provider is required")
	}
	if strings.TrimSpace(req.Code) == "" {
		return nil, fmt.Errorf("code is required")
	}
	if strings.TrimSpace(req.RedirectURL) == "" {
		return nil, fmt.Errorf("redirect_url is required")
	}
	provider, err := coreoidc.NewProvider(ctx, p.issuer)
	if err != nil {
		return nil, err
	}
	oauthConfig := &oauth2.Config{
		ClientID:     p.clientID,
		ClientSecret: p.clientSecret,
		RedirectURL:  req.RedirectURL,
		Endpoint:     provider.Endpoint(),
	}
	options := make([]oauth2.AuthCodeOption, 0, 1)
	if verifier := strings.TrimSpace(req.CodeVerifier); verifier != "" {
		options = append(options, oauth2.SetAuthURLParam("code_verifier", verifier))
	}
	token, err := oauthConfig.Exchange(ctx, req.Code, options...)
	if err != nil {
		return nil, err
	}
	rawIDToken, _ := token.Extra("id_token").(string)
	rawIDToken = strings.TrimSpace(rawIDToken)
	if rawIDToken == "" {
		return nil, fmt.Errorf("upstream token response missing id_token")
	}
	verified, err := provider.Verifier(&coreoidc.Config{ClientID: p.clientID}).Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}
	claims := make(map[string]any)
	if err := verified.Claims(&claims); err != nil {
		return nil, err
	}
	if err := validateNonce(req.Nonce, claims); err != nil {
		return nil, err
	}
	identity, err := schema.NewIdentityFromClaims(claims)
	if err != nil {
		return nil, err
	}
	return &identity, nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func validateNonce(expected string, claims map[string]any) error {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return nil
	}
	actual, _ := claims["nonce"].(string)
	if strings.TrimSpace(actual) != expected {
		return fmt.Errorf("token nonce mismatch")
	}
	return nil
}
