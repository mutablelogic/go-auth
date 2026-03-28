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

package schema

import (
	"context"

	// Packages
	pg "github.com/mutablelogic/go-pg"
)

////////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	SchemaName = "certmanager"
	APIPrefix  = "/cert/v1"
)

const (
	// Maximum number of names to return in a list query
	NameListLimit = 100
)

////////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Bootstrap creates the schema and tables for the certificate manager
// and returns an error if it fails. It is expected that this function
// will be called within a transaction
func Bootstrap(ctx context.Context, conn pg.Conn) error {
	// Create the schema
	if err := pg.SchemaCreate(ctx, conn, SchemaName); err != nil {
		return err
	}
	// Create the tables
	if err := bootstrapName(ctx, conn); err != nil {
		return err
	}
	if err := bootstrapCert(ctx, conn); err != nil {
		return err
	}

	// Commit the transaction
	return nil
}
