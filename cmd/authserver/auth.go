package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/mail"
	"strings"
	"time"

	// Packages
	authcrypto "github.com/djthorpe/go-auth/pkg/crypto"
	jwt "github.com/golang-jwt/jwt/v5"
	client "github.com/mutablelogic/go-client"
	server "github.com/mutablelogic/go-server"
	trace "go.opentelemetry.io/otel/trace"
)

const tokenStoreKey = "auth.token"

///////////////////////////////////////////////////////////////////////////////
// TYPES

type AuthCommands struct {
	Login    LoginCommand    `cmd:"" name:"login" help:"Log in to the auth server with an email address." group:"AUTH"`
	UserInfo UserInfoCommand `cmd:"" name:"userinfo" help:"Get the authenticated userinfo for a local session token." group:"AUTH"`
	Refresh  RefreshCommand  `cmd:"" name:"refresh" help:"Refresh a previously issued local session token." group:"AUTH"`
	Revoke   RevokeCommand   `cmd:"" name:"revoke" help:"Revoke a previously issued local session token." group:"AUTH"`
}

type LoginCommand struct {
	Email string `arg:"" name:"email" help:"Email address to include in the login token."`
	Sub   string `name:"sub" help:"JWT subject claim. Defaults to the email address." default:""`
	Iss   string `name:"iss" help:"JWT issuer claim. Defaults to the configured server endpoint." default:""`
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

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *LoginCommand) Run(ctx server.Cmd) error {
	client, endpoint, err := clientFor(ctx)
	if err != nil {
		return err
	}
	name, email, err := parseLoginAddress(cmd.Email)
	if err != nil {
		return err
	}
	key, err := authcrypto.ParsePrivateKeyPEM(ctx.GetString("privatekey"))
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}

	issuer := cmd.Iss
	if issuer == "" {
		issuer = endpoint
	}
	subject := cmd.Sub
	if subject == "" {
		subject = email
	}
	claims := jwt.MapClaims{
		"iss":   issuer,
		"sub":   subject,
		"email": email,
	}
	if name != "" {
		claims["name"] = name
	}
	response, err := client.Login(ctx.Context(), key, claims)
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

func parseLoginAddress(value string) (string, string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", fmt.Errorf("email is required")
	}
	addr, err := mail.ParseAddress(value)
	if err != nil {
		return "", "", fmt.Errorf("parse email address: %w", err)
	}
	return strings.TrimSpace(addr.Name), strings.TrimSpace(addr.Address), nil
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

var _ server.Cmd = (*fakeCmdCompileOnly)(nil)

type fakeCmdCompileOnly struct{}

func (fakeCmdCompileOnly) Name() string                                        { return "" }
func (fakeCmdCompileOnly) Description() string                                 { return "" }
func (fakeCmdCompileOnly) Version() string                                     { return "" }
func (fakeCmdCompileOnly) Context() context.Context                            { return context.Background() }
func (fakeCmdCompileOnly) Logger() *slog.Logger                                { return slog.Default() }
func (fakeCmdCompileOnly) Tracer() trace.Tracer                                { return nil }
func (fakeCmdCompileOnly) ClientEndpoint() (string, []client.ClientOpt, error) { return "", nil, nil }
func (fakeCmdCompileOnly) Get(string) any                                      { return nil }
func (fakeCmdCompileOnly) GetString(string) string                             { return "" }
func (fakeCmdCompileOnly) Set(string, any) error                               { return nil }
func (fakeCmdCompileOnly) Keys() []string                                      { return nil }
func (fakeCmdCompileOnly) IsTerm() bool                                        { return false }
func (fakeCmdCompileOnly) IsDebug() bool                                       { return false }
func (fakeCmdCompileOnly) HTTPAddr() string                                    { return "" }
func (fakeCmdCompileOnly) HTTPPrefix() string                                  { return "" }
func (fakeCmdCompileOnly) HTTPOrigin() string                                  { return "" }
func (fakeCmdCompileOnly) HTTPTimeout() time.Duration                          { return 0 }
