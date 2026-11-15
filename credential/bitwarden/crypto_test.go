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

package bitwarden

import (
	"encoding/base64"
	"testing"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

// The vectors are from Bitwarden's SDK, in bitwarden-crypto's
// shareable_key.rs and bitwarden-core's access_token.rs

func Test_DeriveShareableKey(t *testing.T) {
	key, err := deriveShareableKey([]byte("&/$%F1a895g67HlX"), "test_key", "")
	require.NoError(t, err)
	assert.Equal(t, "4PV6+PcmF2w7YHRatvyMcVQtI7zvCyssv/wFWmzjiH6Iv9altjmDkuBD1aagLVaLezbthbSe+ktR+U6qswxNnQ==", base64.StdEncoding.EncodeToString(key.bytes()))

	key, err = deriveShareableKey([]byte("67t9b5g67$%Dh89n"), "test_key", "test")
	require.NoError(t, err)
	assert.Equal(t, "F9jVQmrACGx9VUPjuzfMYDjr726JtL300Y3Yg+VYUnVQtQ1s8oImJ5xtp1KALC9h2nav04++1LDW4iFD+infng==", base64.StdEncoding.EncodeToString(key.bytes()))
}

func Test_ParseAccessToken(t *testing.T) {
	token, err := parseAccessToken("0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==")
	require.NoError(t, err)
	assert.Equal(t, "ec2c1d46-6a4b-4751-a310-af9601317f2d", token.id)
	assert.Equal(t, "C2IgxjjLF7qSshsbwe8JGcbM075YXw", token.secret)
	assert.Equal(t, "H9/oIRLtL9nGCQOVDjSMoEbJsjWXSOCb3qeyDt6ckzS3FhyboEDWyTP/CQfbIszNmAVg2ExFganG1FVFGXO/Jg==", base64.StdEncoding.EncodeToString(token.key.bytes()))

	// The encryption key doesn't need to be padded
	_, err = parseAccessToken("0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ")
	assert.NoError(t, err)

	for _, value := range []string{
		"1.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==",
		"0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw.X8vbvA0bduihIDe/qrzIQQ==",
		"ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==",
		"0.not-a-uuid.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==",
		"0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:c2hvcnQ=",
		"",
	} {
		_, err := parseAccessToken(value)
		assert.ErrorIs(t, err, auth.ErrBadParameter, value)
	}
}

func Test_EncryptDecrypt(t *testing.T) {
	key, err := deriveShareableKey([]byte("0123456789abcdef"), "test", "")
	require.NoError(t, err)

	for _, plaintext := range []string{"", "a", "exactly16bytes!!", `{"user":"admin","password":"secret"}`} {
		encrypted, err := key.encrypt([]byte(plaintext))
		require.NoError(t, err)
		assert.Regexp(t, `^2\.[A-Za-z0-9+/=]+\|[A-Za-z0-9+/=]+\|[A-Za-z0-9+/=]+$`, encrypted)
		decrypted, err := key.decrypt(encrypted)
		require.NoError(t, err)
		assert.Equal(t, plaintext, string(decrypted))
	}

	// A different key, a changed MAC, or another type, doesn't decrypt
	encrypted, err := key.encrypt([]byte("secret"))
	require.NoError(t, err)
	other, err := deriveShareableKey([]byte("fedcba9876543210"), "test", "")
	require.NoError(t, err)
	_, err = other.decrypt(encrypted)
	assert.Error(t, err)
	_, err = key.decrypt(encrypted[:len(encrypted)-4] + "AAA=")
	assert.Error(t, err)
	_, err = key.decrypt("7.AAAA")
	assert.Error(t, err)
	_, err = key.decrypt("2.AAAA|BBBB")
	assert.Error(t, err)
}
