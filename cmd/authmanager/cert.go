package main

import (
	"strings"

	// Packages
	cert "github.com/mutablelogic/go-auth/cert/manager"
	server "github.com/mutablelogic/go-server"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type CertFlags struct {
	Enabled     bool     `long:"enabled" description:"Enable the certificate manager" env:"CERT_ENABLED" negatable:""`
	Passphrases []string `long:"passphrase" description:"Passphrase for encrypting private keys. Can be specified multiple times for multiple passphrases." env:"CERT_PASSPHRASE"`
	Schema      string   `long:"schema" description:"Database schema to use for certificate manager tables" default:"" env:"CERT_SCHEMA"`
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (server CertFlags) Options(ctx server.Cmd) []cert.Opt {
	if !server.Enabled {
		return nil
	}

	// Set options based on flags
	opts := []cert.Opt{
		cert.WithTracer(ctx.Tracer()),
	}
	if schema := strings.TrimSpace(server.Schema); schema != "" {
		opts = append(opts, cert.WithSchema(server.Schema))
	}
	for i, passphrase := range server.Passphrases {
		opts = append(opts, cert.WithPassphrase(uint64(i+1), passphrase))
	}

	// Return the options
	return opts
}
