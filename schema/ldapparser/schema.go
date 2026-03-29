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

package ldapparser

////////////////////////////////////////////////////////////////////////////////
// TYPES

type ObjectClassKind string

type AttributeUsage string

type ObjectClassSchema struct {
	NumericOID   string              `json:"numericOid" help:"Numeric object identifier for the object class definition"`
	Name         []string            `json:"name,omitempty" help:"Descriptor names for the object class"`
	Description  string              `json:"description,omitempty" help:"Human-readable description of the object class"`
	SuperClasses []string            `json:"superClasses,omitempty" help:"Superior object classes inherited by this object class"`
	ClassKind    ObjectClassKind     `json:"classKind,omitempty" help:"Object class kind" enum:"ABSTRACT,STRUCTURAL,AUXILIARY"`
	Must         []string            `json:"must,omitempty" help:"Required attribute types for entries using this object class"`
	May          []string            `json:"may,omitempty" help:"Optional attribute types for entries using this object class"`
	Obsolete     bool                `json:"obsolete,omitempty" help:"Whether the object class is marked OBSOLETE"`
	Extensions   map[string][]string `json:"extensions,omitempty" help:"Vendor-specific extension values keyed by extension name"`
}

type AttributeTypeSchema struct {
	NumericOID         string              `json:"numericOid" help:"Numeric object identifier for the attribute type definition"`
	Name               []string            `json:"name,omitempty" help:"Descriptor names for the attribute type"`
	Description        string              `json:"description,omitempty" help:"Human-readable description of the attribute type"`
	SuperType          string              `json:"superType,omitempty" help:"Superior attribute type inherited by this attribute type"`
	Usage              AttributeUsage      `json:"usage,omitempty" help:"Operational usage classification for the attribute type" enum:"userApplications,directoryOperation,distributedOperation,dSAOperation"`
	Syntax             string              `json:"syntax,omitempty" help:"Syntax OID, optionally including a length bound"`
	Obsolete           bool                `json:"obsolete,omitempty" help:"Whether the attribute type is marked OBSOLETE"`
	SingleValue        bool                `json:"singleValue,omitempty" help:"Whether the attribute type allows only a single value"`
	Collective         bool                `json:"collective,omitempty" help:"Whether the attribute type is collective"`
	NoUserModification bool                `json:"noUserModification,omitempty" help:"Whether user modification is prohibited for the attribute type"`
	Extensions         map[string][]string `json:"extensions,omitempty" help:"Vendor-specific extension values keyed by extension name"`
}

////////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	ObjectClassKindAbstract   ObjectClassKind = "ABSTRACT"
	ObjectClassKindStructural ObjectClassKind = "STRUCTURAL"
	ObjectClassKindAuxiliary  ObjectClassKind = "AUXILIARY"
)

const (
	AttributeUsageUserApplications     AttributeUsage = "userApplications"
	AttributeUsageDirectoryOperation   AttributeUsage = "directoryOperation"
	AttributeUsageDistributedOperation AttributeUsage = "distributedOperation"
	AttributeUsageDSAOperation         AttributeUsage = "dSAOperation"
)
