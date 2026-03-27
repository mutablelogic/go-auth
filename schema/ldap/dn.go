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
	// Packages
	ldap "github.com/go-ldap/ldap/v3"
)

////////////////////////////////////////////////////////////////////////////////
// TYPES

type DN ldap.DN

////////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func NewDN(v string) (*DN, error) {
	if dn, err := ldap.ParseDN(v); err != nil {
		return nil, err
	} else {
		return (*DN)(dn), nil
	}
}

////////////////////////////////////////////////////////////////////////////////
// STRINGIFY

func (dn *DN) String() string {
	return (*ldap.DN)(dn).String()
}

////////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (dn *DN) AncestorOf(other *DN) bool {
	return (*ldap.DN)(dn).AncestorOf((*ldap.DN)(other))
}

func (dn *DN) Join(other *DN) *DN {
	if other == nil {
		return dn
	}
	return &DN{
		RDNs: append((*ldap.DN)(dn).RDNs, (*ldap.DN)(other).RDNs...),
	}
}
