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

package schema_test

import (
	"strings"
	"testing"
	"time"

	// Packages
	cert "github.com/mutablelogic/go-auth/cert/cert"
	schema "github.com/mutablelogic/go-auth/cert/schema"
	pg "github.com/mutablelogic/go-pg"
	types "github.com/mutablelogic/go-server/pkg/types"
	assert "github.com/stretchr/testify/assert"
)

func Test_CertListRequest_Select(t *testing.T) {
	assert := assert.New(t)

	// The root certificate is never listed, and the filters are joined
	bind := pg.NewBind()
	_, err := schema.CertListRequest(cert.CertListRequest{
		OffsetLimit: cert.OffsetLimit{Offset: 10, Limit: types.Ptr(uint64(1000))},
		IsCA:        types.Ptr(true),
		Tags:        []string{" web ", "web", "prod"},
	}).Select(bind, pg.List)
	assert.NoError(err)
	where := bind.Get("where").(string)
	assert.True(strings.HasPrefix(where, "WHERE "))
	assert.Contains(where, `cert_row."name" <> `)
	assert.Contains(where, `cert_row."is_ca" = `)
	assert.Equal(cert.RootCertName, bind.Get("root_name"))
	assert.Equal([]string{"web", "prod"}, bind.Get("tags"))

	// The limit is clamped to the maximum
	assert.Equal("LIMIT 100 OFFSET 10", bind.Get("offsetlimit"))

	// A bad tag, a zero subject, and other operations fail
	_, err = schema.CertListRequest(cert.CertListRequest{Tags: []string{"bad tag"}}).Select(pg.NewBind(), pg.List)
	assert.Error(err)
	_, err = schema.CertListRequest(cert.CertListRequest{Subject: types.Ptr(uint64(0))}).Select(pg.NewBind(), pg.List)
	assert.Error(err)
	_, err = schema.CertListRequest{}.Select(pg.NewBind(), pg.Get)
	assert.Error(err)
}

func Test_CertKey_Select(t *testing.T) {
	assert := assert.New(t)

	bind := pg.NewBind()
	_, err := schema.CertKey{Name: " my_cert ", Serial: " 42 "}.Select(bind, pg.Get)
	assert.NoError(err)
	assert.Equal("my_cert", bind.Get("name"))
	assert.Equal("42", bind.Get("serial"))

	for _, key := range []schema.CertKey{{Serial: "1"}, {Name: "my cert", Serial: "1"}, {Name: "a"}, {Name: "a", Serial: "-1"}, {Name: "a", Serial: "x"}} {
		_, err := key.Select(pg.NewBind(), pg.Get)
		assert.Error(err, key)
	}
	_, err = schema.PrivateCertKey{Name: "a", Serial: "1"}.Select(pg.NewBind(), pg.Delete)
	assert.Error(err)
}

func Test_CertWithPrivateKey_Insert(t *testing.T) {
	assert := assert.New(t)
	now := time.Now()

	certificate := func(name string, signer *cert.CertKey, ca bool) schema.CertWithPrivateKey {
		return schema.CertWithPrivateKey{Certificate: cert.Certificate{
			CertKey:   cert.CertKey{Name: name, Serial: "1"},
			Signer:    signer,
			SubjectID: types.Ptr(uint64(1)),
			NotBefore: now,
			NotAfter:  now.Add(time.Hour),
			IsCA:      ca,
		}}
	}
	root := cert.CertKey{Name: cert.RootCertName, Serial: "1"}

	// Root and signed certificates are inserted, enabled by default
	bind := pg.NewBind()
	_, err := certificate(cert.RootCertName, nil, true).Insert(bind)
	assert.NoError(err)
	assert.Equal(true, bind.Get("enabled"))
	assert.Equal([]string{}, bind.Get("tags"))
	_, err = certificate("leaf", &root, false).Insert(pg.NewBind())
	assert.NoError(err)

	// A root which isn't a CA or is signed, or another unsigned one, fails
	_, err = certificate(cert.RootCertName, nil, false).Insert(pg.NewBind())
	assert.Error(err)
	_, err = certificate(cert.RootCertName, &root, true).Insert(pg.NewBind())
	assert.Error(err)
	_, err = certificate("leaf", nil, false).Insert(pg.NewBind())
	assert.Error(err)

	// It expires after it starts
	c := certificate("leaf", &root, false)
	c.NotAfter = now.Add(-time.Hour)
	_, err = c.Insert(pg.NewBind())
	assert.Error(err)
}

func Test_Meta_Update(t *testing.T) {
	assert := assert.New(t)

	// Nothing to update
	assert.Error(schema.CertMeta{}.Update(pg.NewBind()))
	assert.Error(schema.SubjectMeta{}.Update(pg.NewBind()))

	// Only what's set is patched
	bind := pg.NewBind()
	assert.NoError(schema.CertMeta{Enabled: types.Ptr(false)}.Update(bind))
	assert.Contains(bind.Get("patch"), `"enabled" = `)
	assert.NotContains(bind.Get("patch"), `"tags"`)

	bind = pg.NewBind()
	assert.NoError(schema.SubjectMeta{Org: types.Ptr(" Example ")}.Update(bind))
	assert.Equal(`"organizationName" = @organizationName`, bind.Get("patch"))
	assert.Equal(types.Ptr("Example"), bind.Get("organizationName"))
}
