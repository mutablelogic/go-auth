// Copyright 2026 David Thorpe
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"os"
	"strings"

	// Packages
	cert "github.com/mutablelogic/go-auth/cert/manager"
	crypto "github.com/mutablelogic/go-auth/crypto"
	server "github.com/mutablelogic/go-server"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type CertFlags struct {
	Enabled    bool     `help:"Enable the certificate manager" env:"CERT_ENABLED" default:"true" negatable:""`
	Passphrase []string `help:"Passphrase for encrypting private keys. Can be specified multiple times for multiple passphrases." env:"CERT_PASSPHRASE"`
	Schema     string   `help:"Database schema to use for certificate manager tables" env:"CERT_SCHEMA"`
}

type BootstrapFlags struct {
	RootCertPEM string `arg:"" name:"certificate-pem" type:"FILE" help:"Path to a PEM bundle containing the root certificate and private key" required:""`
	Passphrase  string `help:"Passphrase used to decrypt an encrypted private key inside the certificate PEM bundle before import." env:"CERT_PASSPHRASE"`
	Schema      string `help:"Database schema to use for certificate manager tables" env:"CERT_SCHEMA"`
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
	for i, passphrase := range server.Passphrase {
		opts = append(opts, cert.WithPassphrase(uint64(i+1), passphrase))
	}

	// Return the options
	return opts
}

func (flags BootstrapFlags) Options(ctx server.Cmd) ([]cert.Opt, error) {
	opts := []cert.Opt{
		cert.WithTracer(ctx.Tracer()),
	}

	// Add database schema
	if schema := strings.TrimSpace(flags.Schema); schema != "" {
		opts = append(opts, cert.WithSchema(flags.Schema))
	}

	// Add passphrase for storage
	if flags.Passphrase != "" {
		opts = append(opts, cert.WithPassphrase(1, flags.Passphrase))
	}

	// Read the certificate PEM file
	if data, err := os.ReadFile(flags.RootCertPEM); err != nil {
		return nil, err
	} else if key, err := crypto.ParsePrivateKeyPEM(data, flags.Passphrase); err != nil {
		return nil, err
	} else if x509cert, err := crypto.ParseCertificatePEM(data); err != nil {
		return nil, err
	} else {
		opts = append(opts, cert.WithRoot(key, x509cert))
	}

	// Return cert options
	return opts, nil
}
