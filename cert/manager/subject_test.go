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

package manager_test

import (
	"context"
	"testing"

	// Packages
	cert "github.com/mutablelogic/go-auth/cert/cert"
	manager "github.com/mutablelogic/go-auth/cert/manager"
	test "github.com/mutablelogic/go-auth/cert/test"
	pg "github.com/mutablelogic/go-pg"
	types "github.com/mutablelogic/go-server/pkg/types"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_subject(t *testing.T) {
	ctx := context.Background()
	m := test.IsolatedManager(t, manager.WithPassphrase(1, "root-secret-1"), manager.WithGeneratedRoot("Subject Root CA"))

	// A new subject, and an identical one, which is the same
	created, err := m.CreateSubject(ctx, cert.SubjectMeta{Org: types.Ptr(" Example "), Country: types.Ptr("GB")})
	require.NoError(t, err)
	assert.NotZero(t, created.ID)
	assert.Equal(t, "Example", types.Value(created.Org))
	assert.Equal(t, uint64(0), created.Certs)
	assert.Equal(t, "O=Example,C=GB", types.Value(created.Subject))
	same, err := m.CreateSubject(ctx, cert.SubjectMeta{Org: types.Ptr("Example"), Country: types.Ptr("GB")})
	require.NoError(t, err)
	assert.Equal(t, created.ID, same.ID)

	// An empty one isn't
	_, err = m.CreateSubject(ctx, cert.SubjectMeta{Org: types.Ptr(" ")})
	assert.EqualError(t, err, "Bad Request: subject has no fields")

	// One which isn't used is updated, and deleted
	got, err := m.GetSubject(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, got.ID)
	updated, err := m.UpdateSubject(ctx, created.ID, cert.SubjectMeta{City: types.Ptr("London"), Country: types.Ptr("")})
	require.NoError(t, err)
	assert.Equal(t, "London", types.Value(updated.City))
	assert.Nil(t, updated.Country, "an empty field is removed")
	assert.Equal(t, "Example", types.Value(updated.Org), "a field which isn't set is kept")
	_, err = m.UpdateSubject(ctx, created.ID, cert.SubjectMeta{})
	assert.EqualError(t, err, "Bad Request: nothing to update")
	deleted, err := m.DeleteSubject(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, deleted.ID)
	_, err = m.GetSubject(ctx, created.ID)
	assert.ErrorIs(t, err, pg.ErrNotFound)

	// One which a certificate uses is listed with the count, and isn't
	// changed or deleted
	ca, err := m.CreateCA(ctx, cert.CreateCertRequest{Name: "subject_ca", Subject: &cert.SubjectMeta{Org: types.Ptr("Used Org")}})
	require.NoError(t, err)
	used := ca.Subject.ID
	list, err := m.ListSubjects(ctx, cert.SubjectListRequest{})
	require.NoError(t, err)
	var count uint64
	for _, s := range list.Body {
		if s.ID == used {
			count = s.Certs
		}
	}
	assert.Equal(t, uint64(1), count)
	assert.Equal(t, uint64(len(list.Body)), list.Count)
	_, err = m.UpdateSubject(ctx, used, cert.SubjectMeta{Org: types.Ptr("Changed")})
	assert.EqualError(t, err, "Conflict: subject "+types.Stringify(used)+" is used by 1 certificates")
	_, err = m.DeleteSubject(ctx, used)
	assert.EqualError(t, err, "Conflict: subject "+types.Stringify(used)+" is used by 1 certificates")
	got, err = m.GetSubject(ctx, used)
	require.NoError(t, err)
	assert.Equal(t, "Used Org", types.Value(got.Org))

	// One which isn't stored isn't found
	_, err = m.UpdateSubject(ctx, 999999, cert.SubjectMeta{Org: types.Ptr("x")})
	assert.ErrorIs(t, err, pg.ErrNotFound)
	_, err = m.DeleteSubject(ctx, 999999)
	assert.ErrorIs(t, err, pg.ErrNotFound)
}
