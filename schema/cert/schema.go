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
	_ "embed"
	"time"
)

////////////////////////////////////////////////////////////////////////////////
// GLOBALS

//go:embed objects.sql
var Objects string

//go:embed queries.sql
var Queries string

const (
	SchemaName   = "cert"
	RootCertName = "$root$"
)

const (
	// DefaultCACertExpiry is the default validity period for intermediate
	// certificate authorities.
	DefaultCACertExpiry = 5 * 365 * 24 * time.Hour

	// DefaultCertExpiry is the default validity period for leaf certificates.
	DefaultCertExpiry = 90 * 24 * time.Hour
)

const (
	// Maximum number of subjects to return in a list query
	SubjectListLimit = 100

	// Maximum number of certificates to return in a list query
	CertListLimit = 100
)
