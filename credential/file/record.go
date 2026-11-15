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

package file

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"
)

////////////////////////////////////////////////////////////////////////////////
// TYPES

// record is a credential's file: the passphrase version, as eight
// big-endian bytes, the length of the description, as four big-endian
// bytes, the description, which isn't encrypted, as it isn't secret, and
// the encrypted value
type record struct {
	version     uint64
	description string
	encrypted   []byte
}

////////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	// versionSize is the size of the passphrase version at the start of a
	// file, and lengthSize of the description's length after it
	versionSize = 8
	lengthSize  = 4

	// maxDescription is the most bytes a description can have
	maxDescription = 4096
)

var (
	// errInvalid is the error of a file which isn't a record
	errInvalid = errors.New("invalid credential file")
)

////////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// encode returns the record's file
func (r record) encode() []byte {
	data := make([]byte, 0, versionSize+lengthSize+len(r.description)+len(r.encrypted))
	data = binary.BigEndian.AppendUint64(data, r.version)
	data = binary.BigEndian.AppendUint32(data, uint32(len(r.description)))
	data = append(data, r.description...)
	return append(data, r.encrypted...)
}

// decodeRecord returns the record of a file, or errInvalid, when it's too
// short, its description is too long or isn't UTF-8, or it has no value
func decodeRecord(data []byte) (*record, error) {
	if len(data) < versionSize+lengthSize {
		return nil, fmt.Errorf("%w: it's too short", errInvalid)
	}
	version := binary.BigEndian.Uint64(data[:versionSize])
	length := binary.BigEndian.Uint32(data[versionSize : versionSize+lengthSize])
	data = data[versionSize+lengthSize:]
	if length > maxDescription || int(length) > len(data) {
		return nil, fmt.Errorf("%w: its description's length is %d", errInvalid, length)
	}
	description := data[:length]
	if !utf8.Valid(description) {
		return nil, fmt.Errorf("%w: its description isn't UTF-8", errInvalid)
	} else if len(data) == int(length) {
		return nil, fmt.Errorf("%w: it has no value", errInvalid)
	}
	return &record{version: version, description: string(description), encrypted: data[length:]}, nil
}
