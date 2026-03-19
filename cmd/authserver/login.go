package main

import (
	"encoding/json"
	"fmt"

	// Packages
	jwt "github.com/golang-jwt/jwt/v5"
	server "github.com/mutablelogic/go-server"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type ClientCommands struct {
	Login LoginCommand `cmd:"" name:"login" help:"Log in to the auth server with an email address." group:"CLIENT"`
}

type LoginCommand struct {
	Email string `arg:"" name:"email" help:"Email address to include in the login token."`
	Sub   string `name:"sub" help:"JWT subject claim. Defaults to the email address." default:""`
	Iss   string `name:"iss" help:"JWT issuer claim. Defaults to the configured server endpoint." default:""`
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *LoginCommand) Run(ctx server.Cmd) error {
	client, endpoint, err := clientFor(ctx)
	if err != nil {
		return err
	}
	pem := ctx.GetString("privatekey")

	issuer := cmd.Iss
	if issuer == "" {
		issuer = endpoint
	}
	subject := cmd.Sub
	if subject == "" {
		subject = cmd.Email
	}

	claims := jwt.MapClaims{
		"iss":   issuer,
		"sub":   subject,
		"email": cmd.Email,
	}

	response, err := client.Login(ctx.Context(), pem, claims)
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
