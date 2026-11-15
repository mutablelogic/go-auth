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

package credential_test

import (
	"context"
	"encoding/json"
	"testing"

	// Packages
	credential "github.com/mutablelogic/go-auth/credential"
	awscredential "github.com/mutablelogic/go-auth/credential/aws"
	bitwarden "github.com/mutablelogic/go-auth/credential/bitwarden"
	filecredential "github.com/mutablelogic/go-auth/credential/file"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

// decrypter can also return a value with its passphrase, and rotator can
// also rotate
type decrypter struct{ plain }
type rotator struct{ decrypter }

func (decrypter) Decrypt(context.Context, string, string) (json.RawMessage, error) { return nil, nil }
func (rotator) Rotate(context.Context, string) error                               { return nil }

// plain is a manager which can only store, list and delete
type plain struct{}

func (plain) Expand(context.Context, string) (string, error)        { return "", nil }
func (plain) Get(context.Context, string) (json.RawMessage, error)  { return nil, nil }
func (plain) Set(context.Context, string, json.RawMessage) error    { return nil }
func (plain) List(context.Context) ([]credential.Credential, error) { return nil, nil }
func (plain) Delete(context.Context, string) error                  { return nil }

func Test_FeaturesOf(t *testing.T) {
	assert.Equal(t, credential.Features{Backend: "aws"}, credential.FeaturesOf("aws", plain{}))
	assert.Equal(t, credential.Features{Backend: "x", Decrypt: true}, credential.FeaturesOf("x", decrypter{}))
	assert.Equal(t, credential.Features{Backend: "file", Decrypt: true, Rotate: true}, credential.FeaturesOf("file", rotator{}))
}

func Test_FeaturesOfBackends(t *testing.T) {
	// The file manager decrypts and rotates, and AWS and Bitwarden do
	// neither, as they encrypt with their own keys
	file, err := filecredential.New(t.TempDir())
	require.NoError(t, err)
	assert.Equal(t, credential.Features{Backend: "file", Decrypt: true, Rotate: true}, credential.FeaturesOf("file", file))

	aws, err := awscredential.New(context.Background(), awscredential.WithRegion("eu-west-1"), awscredential.WithCredentials("AKIDEXAMPLE", "secret", ""))
	require.NoError(t, err)
	assert.Equal(t, credential.Features{Backend: "aws"}, credential.FeaturesOf("aws", aws))

	bw, err := bitwarden.New(bitwarden.WithAccessToken("0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ=="))
	require.NoError(t, err)
	assert.Equal(t, credential.Features{Backend: "bitwarden"}, credential.FeaturesOf("bitwarden", bw))
}
