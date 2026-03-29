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

//go:build !client

package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	// Packages
	manager "github.com/djthorpe/go-auth/pkg/certmanager"
	server "github.com/mutablelogic/go-server"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type ServerCommands struct {
	Bootstrap BootstrapCommand `cmd:"" name:"bootstrap" help:"Bootstrap by importing a root certificate PEM bundle." group:"SERVER"`
}

type ServerCommand struct {
	PostgresFlags `embed:"" prefix:"pg."`
}

type BootstrapCommand struct {
	ServerCommand
	StoragePassphrase     []string `name:"storage-passphrase" env:"CERTMANAGER_PASSPHRASES" help:"Passphrase used to encrypt the stored root private key in PostgreSQL. Repeat the flag to define versions 1, 2, 3, and so on in order."`
	CertificatePassphrase string   `name:"certificate-passphrase" env:"CERTMANAGER_CERTIFICATE_PASSPHRASE" help:"Passphrase used to decrypt an encrypted private key inside the certificate PEM bundle before import."`
	RootCertPEM           string   `name:"certificate-pem" placeholder:"PATH" help:"Path to a PEM bundle containing the root certificate and private key" required:""`
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (bootstrap *BootstrapCommand) Run(ctx server.Cmd) error {
	rootOpt, err := bootstrap.rootOpt()
	if err != nil {
		return err
	}
	storageOpts, err := bootstrap.storagePassphraseOpts()
	if err != nil {
		return err
	}
	storageOpts = append(storageOpts, rootOpt)

	return bootstrap.withManager(ctx, func(manager *manager.Manager, v string) error {
		ctx.Logger().Info("Bootstrapped certificate manager", "version", v, "action", "import", "certificate_pem", bootstrap.RootCertPEM, "storage_passphrase_versions", len(bootstrap.StoragePassphrase))
		return nil
	}, storageOpts...)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// WithManager creates the resource manager, registers all resource instances
// (logger, otel, handlers, router) in dependency order, invokes fn, then
// closes the manager regardless of whether fn returned an error.
func (server *ServerCommand) withManager(ctx server.Cmd, fn func(*manager.Manager, string) error, extraOpts ...manager.Opt) error {
	// Connect to the database, if configured
	conn, err := server.Connect(ctx)
	if err != nil {
		return err
	} else if conn == nil {
		return fmt.Errorf("database connection is required")
	}

	// Cert manager options
	opts := []manager.Opt{
		manager.WithTracer(ctx.Tracer()),
	}
	opts = append(opts, extraOpts...)

	// Create the manager and run the server
	manager, err := manager.New(ctx.Context(), conn, opts...)
	if err != nil {
		return err
	}
	defer manager.Close()

	// Invoke the function with the manager and version string
	return fn(manager, ctx.Version())
}

func (bootstrap *BootstrapCommand) rootOpt() (manager.Opt, error) {
	data, err := os.ReadFile(bootstrap.RootCertPEM)
	if err != nil {
		return nil, err
	}
	normalized, err := normalizeRootPEM(data, bootstrap.CertificatePassphrase)
	if err != nil {
		return nil, err
	}
	return manager.WithRoot(string(normalized)), nil
}

func (bootstrap *BootstrapCommand) storagePassphraseOpts() ([]manager.Opt, error) {
	if len(bootstrap.StoragePassphrase) == 0 {
		return nil, fmt.Errorf("at least one storage passphrase is required")
	}

	opts := make([]manager.Opt, 0, len(bootstrap.StoragePassphrase))
	for i, passphrase := range bootstrap.StoragePassphrase {
		opts = append(opts, manager.WithPassphrase(uint64(i+1), passphrase))
	}

	return opts, nil
}

func normalizeRootPEM(data []byte, passphrase string) ([]byte, error) {
	var normalized bytes.Buffer
	data = bytes.TrimSpace(data)

	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("invalid PEM block")
		}

		switch block.Type {
		case "RSA PRIVATE KEY", "PRIVATE KEY":
			if x509.IsEncryptedPEMBlock(block) {
				if passphrase == "" {
					return nil, fmt.Errorf("certificate passphrase is required for encrypted private key")
				}
				der, err := x509.DecryptPEMBlock(block, []byte(passphrase))
				if err != nil {
					return nil, fmt.Errorf("decrypt private key: %w", err)
				}
				if err := pem.Encode(&normalized, &pem.Block{Type: block.Type, Bytes: der}); err != nil {
					return nil, err
				}
			} else {
				if err := pem.Encode(&normalized, block); err != nil {
					return nil, err
				}
			}
		case "ENCRYPTED PRIVATE KEY":
			return nil, fmt.Errorf("encrypted PKCS#8 private keys are not supported")
		default:
			if err := pem.Encode(&normalized, block); err != nil {
				return nil, err
			}
		}

		data = bytes.TrimSpace(rest)
	}

	return normalized.Bytes(), nil
}
