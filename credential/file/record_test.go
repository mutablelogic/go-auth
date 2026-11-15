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
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	// Packages
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_Record(t *testing.T) {
	t.Run("RoundTrip", func(t *testing.T) {
		for _, r := range []record{
			{version: 1, description: "", encrypted: []byte{1, 2, 3}},
			{version: 7, description: "The API token, ünïcode", encrypted: []byte("encrypted")},
		} {
			got, err := decodeRecord(r.encode())
			require.NoError(t, err)
			assert.Equal(t, r, *got)
		}
	})

	t.Run("Layout", func(t *testing.T) {
		// The version, the description's length, the description, and then
		// the value
		data := record{version: 2, description: "ab", encrypted: []byte{9}}.encode()
		assert.Equal(t, uint64(2), binary.BigEndian.Uint64(data[:8]))
		assert.Equal(t, uint32(2), binary.BigEndian.Uint32(data[8:12]))
		assert.Equal(t, []byte("ab"), data[12:14])
		assert.Equal(t, []byte{9}, data[14:])
	})

	t.Run("Invalid", func(t *testing.T) {
		valid := record{version: 1, description: "desc", encrypted: []byte{1}}.encode()
		long := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint64(nil, 1), maxDescription+1)
		long = append(long, bytes.Repeat([]byte("x"), maxDescription+2)...)
		notUTF8 := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint64(nil, 1), 1)
		notUTF8 = append(notUTF8, 0xff, 1)
		for name, data := range map[string][]byte{
			"empty":       nil,
			"version":     valid[:8],
			"length":      valid[:11],
			"description": valid[:14],
			"no value":    valid[:16],
			"too long":    long,
			"not UTF-8":   notUTF8,
		} {
			_, err := decodeRecord(data)
			assert.True(t, errors.Is(err, errInvalid), name)
		}
	})
}
