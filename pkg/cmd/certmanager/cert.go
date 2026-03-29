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

package certmanager

import (
	"fmt"

	// Packages
	certclient "github.com/djthorpe/go-auth/pkg/httpclient/certmanager"
	schema "github.com/djthorpe/go-auth/schema/cert"
	server "github.com/mutablelogic/go-server"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type CertCommands struct {
	Certs ListCertsCommand `cmd:"" name:"certs" help:"List certificates." group:"CERTIFICATE MANAGER"`
}

type ListCertsCommand schema.CertListRequest

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *ListCertsCommand) Run(ctx server.Cmd) error {
	return withUnauthenticatedClient(ctx, func(client *certclient.Client, endpoint string) error {
		certs, err := client.ListCerts(ctx.Context(), schema.CertListRequest(*cmd))
		if err != nil {
			return err
		}
		fmt.Println(certs)
		return nil
	})
}
