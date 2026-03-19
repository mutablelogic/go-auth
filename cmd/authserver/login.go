package main

import (
	"encoding/json"
	"fmt"

	// Packages
	authcrypto "github.com/djthorpe/go-auth/pkg/crypto"
	jwt "github.com/golang-jwt/jwt/v5"
	server "github.com/mutablelogic/go-server"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type ClientCommands struct {
	Login   LoginCommand   `cmd:"" name:"login" help:"Log in to the auth server with an email address." group:"CLIENT"`
	Refresh RefreshCommand `cmd:"" name:"refresh" help:"Refresh a previously issued local session token." group:"CLIENT"`
	Revoke  RevokeCommand  `cmd:"" name:"revoke" help:"Revoke a previously issued local session token." group:"CLIENT"`
}

type LoginCommand struct {
	Email string `arg:"" name:"email" help:"Email address to include in the login token."`
	Sub   string `name:"sub" help:"JWT subject claim. Defaults to the email address." default:""`
	Iss   string `name:"iss" help:"JWT issuer claim. Defaults to the configured server endpoint." default:""`
}

type RefreshCommand struct {
	Token string `arg:"" name:"token" help:"Previously issued local session token."`
}

type RevokeCommand struct {
	Token string `arg:"" name:"token" help:"Previously issued local session token."`
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *LoginCommand) Run(ctx server.Cmd) error {
	client, endpoint, err := clientFor(ctx)
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
		subject = cmd.Email
	}
	response, err := client.Login(ctx.Context(), key, jwt.MapClaims{
		"iss":   issuer,
		"sub":   subject,
		"email": cmd.Email,
	})
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

func (cmd *RefreshCommand) Run(ctx server.Cmd) error {
	client, _, err := clientFor(ctx)
	if err != nil {
		return err
	}

	response, err := client.Refresh(ctx.Context(), cmd.Token)
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

	response, err := client.Revoke(ctx.Context(), cmd.Token)
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
