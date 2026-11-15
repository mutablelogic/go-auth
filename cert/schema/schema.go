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

// Package schema has the PostgreSQL store's tables and queries, and binds
// the certificate types in cert/cert to them. Each type here is one of
// cert/cert's, so converts to and from it, such as (*Certificate)(&c).
package schema

import (
	_ "embed"
)

////////////////////////////////////////////////////////////////////////////////
// GLOBALS

//go:embed objects.sql
var Objects string

//go:embed queries.sql
var Queries string

const (
	SchemaName = "cert"
)

// LockName serializes creating certificates with a name, bound as name, until
// the transaction ends. It's run with Exec, which doesn't look up the named
// queries.
const LockName = `SELECT pg_advisory_xact_lock(hashtext(${'schema'} || '.' || @name))`

const (
	// Maximum number of subjects to return in a list query
	SubjectListLimit = 100

	// Maximum number of certificates to return in a list query
	CertListLimit = 100
)
