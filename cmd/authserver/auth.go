package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	// Packages
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	webcallback "github.com/djthorpe/go-auth/pkg/webcallback"
	server "github.com/mutablelogic/go-server"
	browser "github.com/pkg/browser"
)

const (
	tokenStoreKey          = "auth.token"
	defaultOIDCRedirectURL = "http://127.0.0.1:8085/callback"
)

var openBrowserURL = browser.OpenURL

///////////////////////////////////////////////////////////////////////////////
// TYPES

type AuthCommands struct {
	Login      LoginCommand      `cmd:"" name:"login" help:"Start a login flow for the selected auth provider." group:"AUTH"`
	UserInfo   UserInfoCommand   `cmd:"" name:"userinfo" help:"Get the authenticated userinfo for a local session token." group:"AUTH"`
	Refresh    RefreshCommand    `cmd:"" name:"refresh" help:"Refresh a previously issued local session token." group:"AUTH"`
	Revoke     RevokeCommand     `cmd:"" name:"revoke" help:"Revoke a previously issued local session token." group:"AUTH"`
	Config     ConfigCommand     `cmd:"" name:"config" help:"Get the public auth provider configuration." group:"AUTH"`
	OIDCConfig OIDCConfigCommand `cmd:"" name:"oidc" help:"Get the local OpenID Connect discovery document." group:"AUTH"`
}

type LoginCommand struct {
	Provider    string `arg:"" name:"provider" help:"Configured auth provider key such as 'google' or 'local'."`
	RedirectURL string `name:"redirect-url" help:"OAuth callback URL for interactive provider login." default:"http://127.0.0.1:8085/callback"`
}

type RefreshCommand struct {
	Token string `arg:"" optional:"" name:"token" help:"Previously issued local session token. Defaults to the stored token."`
}

type UserInfoCommand struct {
	Token string `arg:"" optional:"" name:"token" help:"Previously issued local session token. Defaults to the stored token."`
}

type RevokeCommand struct {
	Token string `arg:"" optional:"" name:"token" help:"Previously issued local session token. Defaults to the stored token."`
}

type ConfigCommand struct{}

type OIDCConfigCommand struct {
	Provider string `arg:"" optional:"" name:"provider" help:"Configured auth provider key. Defaults to 'local'."`
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *LoginCommand) Run(ctx server.Cmd) error {
	client, _, err := clientFor(ctx)
	if err != nil {
		return err
	}
	provider := strings.TrimSpace(cmd.Provider)
	if provider == "" {
		return fmt.Errorf("provider is required")
	}
	callback, err := webcallback.New(cmd.RedirectURL)
	if err != nil {
		return err
	}
	bootstrap, err := client.OAuthLoginBootstrap(ctx.Context(), provider, callback.URL())
	if err != nil {
		return err
	}
	if err := openAuthorizationURL(bootstrap); err != nil {
		return err
	}
	result, err := callback.Run(ctx.Context())
	if err != nil {
		return err
	}
	code, err := authorizationCodeFromCallback(bootstrap, result)
	if err != nil {
		return err
	}
	response, err := client.LoginCode(ctx.Context(), provider, bootstrap, code)
	if err != nil {
		return err
	}
	if err := storeToken(ctx, response.Token); err != nil {
		return err
	}
	data, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func authorizationFlowOutput(flow *oidc.AuthorizationCodeFlow) (string, error) {
	if flow == nil {
		return "", fmt.Errorf("authorization flow is required")
	}
	data, err := json.MarshalIndent(flow, "", "  ")
	if err != nil {
		return "", err
	}
	if uri := strings.TrimSpace(flow.AuthorizationURL); uri != "" {
		return "Authorization URL:\n" + uri + "\n\n" + string(data), nil
	}
	return string(data), nil
}

func openAuthorizationURL(flow *oidc.AuthorizationCodeFlow) error {
	if flow == nil {
		return fmt.Errorf("authorization flow is required")
	}
	uri := strings.TrimSpace(flow.AuthorizationURL)
	if uri == "" {
		return nil
	}
	if err := openBrowserURL(uri); err != nil {
		return fmt.Errorf("open authorization URL: %w", err)
	}
	return nil
}

func authorizationCodeFromCallback(flow *oidc.AuthorizationCodeFlow, result *webcallback.Result) (string, error) {
	if flow == nil {
		return "", fmt.Errorf("authorization flow is required")
	}
	if result == nil {
		return "", fmt.Errorf("callback result is required")
	}
	if expected := strings.TrimSpace(flow.State); expected != "" {
		if actual := strings.TrimSpace(result.State()); actual != expected {
			return "", fmt.Errorf("callback state mismatch")
		}
	}
	code := strings.TrimSpace(result.Code())
	if code == "" {
		return "", fmt.Errorf("callback code is required")
	}
	return code, nil
}

func (cmd *RefreshCommand) Run(ctx server.Cmd) error {
	client, _, err := clientFor(ctx)
	if err != nil {
		return err
	}
	token, err := tokenFromArgOrStore(ctx, cmd.Token)
	if err != nil {
		return err
	}

	response, err := client.Refresh(ctx.Context(), token)
	if err != nil {
		return err
	}
	if err := storeToken(ctx, response.Token); err != nil {
		return err
	}

	data, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func (cmd *UserInfoCommand) Run(ctx server.Cmd) error {
	client, _, err := clientFor(ctx)
	if err != nil {
		return err
	}
	token, err := tokenFromArgOrStore(ctx, cmd.Token)
	if err != nil {
		return err
	}

	response, err := client.UserInfo(ctx.Context(), token)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func (cmd *RevokeCommand) Run(ctx server.Cmd) error {
	client, _, err := clientFor(ctx)
	if err != nil {
		return err
	}
	token, err := tokenFromArgOrStore(ctx, cmd.Token)
	if err != nil {
		return err
	}

	if err := client.Revoke(ctx.Context(), token); err != nil {
		return err
	}
	if err := clearStoredToken(ctx); err != nil {
		return err
	}
	fmt.Println("revoked")
	return nil
}

func (cmd *ConfigCommand) Run(ctx server.Cmd) error {
	client, _, err := clientFor(ctx)
	if err != nil {
		return err
	}

	response, err := client.AuthConfig(ctx.Context())
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func (cmd *OIDCConfigCommand) Run(ctx server.Cmd) error {
	client, _, err := clientFor(ctx)
	if err != nil {
		return err
	}
	config, err := client.AuthConfig(ctx.Context())
	if err != nil {
		return err
	}
	issuer, err := oidcIssuerForProvider(config, cmd.Provider)
	if err != nil {
		return err
	}

	response, err := client.OIDCConfig(ctx.Context(), issuer)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func oidcIssuerForProvider(config oidc.PublicClientConfigurations, provider string) (string, error) {
	key := strings.TrimSpace(provider)
	if key == "" {
		key = oidc.OAuthClientKeyLocal
	}
	cfg, ok := config[key]
	if !ok {
		keys := make([]string, 0, len(config))
		for key := range config {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		return "", fmt.Errorf("unknown auth provider %q (available: %s)", key, strings.Join(keys, ", "))
	}
	issuer := strings.TrimSpace(cfg.Issuer)
	if issuer == "" {
		return "", fmt.Errorf("auth provider %q has no issuer", key)
	}
	return issuer, nil
}

func tokenFromArgOrStore(ctx server.Cmd, value string) (string, error) {
	if token := strings.TrimSpace(value); token != "" {
		return token, nil
	}
	if ctx == nil {
		return "", fmt.Errorf("login required")
	}
	if token := strings.TrimSpace(ctx.GetString(tokenStoreKey)); token != "" {
		return token, nil
	}
	return "", fmt.Errorf("login required")
}

func storeToken(ctx server.Cmd, token string) error {
	if ctx == nil {
		return nil
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return nil
	}
	if err := ctx.Set(tokenStoreKey, token); err != nil {
		return fmt.Errorf("store token: %w", err)
	}
	return nil
}

func clearStoredToken(ctx server.Cmd) error {
	if ctx == nil {
		return nil
	}
	if err := ctx.Set(tokenStoreKey, nil); err != nil {
		return fmt.Errorf("clear token: %w", err)
	}
	return nil
}
