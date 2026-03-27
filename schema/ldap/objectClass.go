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
	types "github.com/mutablelogic/go-server/pkg/types"
	parser "github.com/yinyin/go-ldap-schema-parser"
)

//////////////////////////////////////////////////////////////////////////////////
// TYPES

type ObjectClass struct {
	*parser.ObjectClassSchema
}

//////////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func ParseObjectClass(v string) (*ObjectClass, error) {
	schema, err := parser.ParseObjectClassSchema(v)
	if err != nil {
		return nil, err
	}
	return types.Ptr(ObjectClass{schema}), nil
}

//////////////////////////////////////////////////////////////////////////////////
// STRINGIFY

func (o ObjectClass) String() string {
	return types.Stringify(o)
}
