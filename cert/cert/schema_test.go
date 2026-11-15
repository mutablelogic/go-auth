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

package cert_test

import (
	"crypto/x509/pkix"
	"testing"
	"time"

	// Packages
	cert "github.com/mutablelogic/go-auth/cert/cert"
	types "github.com/mutablelogic/go-server/pkg/types"
	assert "github.com/stretchr/testify/assert"
)

func Test_NormalizeTags(t *testing.T) {
	assert := assert.New(t)

	tags, err := cert.NormalizeTags([]string{" a ", "", "b", "a"})
	assert.NoError(err)
	assert.Equal([]string{"a", "b"}, tags)

	tags, err = cert.NormalizeTags(nil)
	assert.NoError(err)
	assert.Equal([]string{}, tags)

	_, err = cert.NormalizeTags([]string{"not a tag"})
	assert.Error(err)
}

func Test_CertKey_Validate(t *testing.T) {
	assert := assert.New(t)

	key, err := cert.CertKey{Name: " a ", Serial: " 12 "}.Validate()
	assert.NoError(err)
	assert.Equal(cert.CertKey{Name: "a", Serial: "12"}, key)

	_, err = cert.CertKey{Name: cert.RootCertName, Serial: "1"}.Validate()
	assert.NoError(err)
	assert.True(cert.Certificate{CertKey: cert.CertKey{Name: cert.RootCertName}}.IsRoot())
}

func Test_SubjectMeta(t *testing.T) {
	assert := assert.New(t)

	// Merging keeps what isn't patched, and an empty value removes it
	merged := cert.MergeSubjectMeta(
		cert.SubjectMeta{Org: types.Ptr(" Example "), City: types.Ptr("London")},
		&cert.SubjectMeta{City: types.Ptr(" "), Country: types.Ptr("GB")},
	)
	assert.Equal(cert.SubjectMeta{Org: types.Ptr("Example"), Country: types.Ptr("GB")}, merged)

	// To and from an X.509 name
	assert.Equal(merged, cert.SubjectMetaFromPKIXName(merged.PKIXName()))
	assert.Equal(pkix.Name{Organization: []string{"Example"}, Country: []string{"GB"}}, merged.PKIXName())

	// A reference has the name, with the common name
	ref := cert.SubjectRefFromMeta(1, merged, time.Time{}, types.Ptr("host"))
	assert.Equal("CN=host,O=Example,C=GB", types.Value(ref.Name))
}
