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

package ldap_test

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	// Packages
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	ldap "github.com/mutablelogic/go-server/pkg/ldap"
	schema "github.com/mutablelogic/go-server/pkg/ldap/schema"
	assert "github.com/stretchr/testify/assert"
)

const (
	// https://github.com/shadowbq/FreeIPA-Configuration
	User, Pass = "uid=admin,cn=users,cn=accounts,dc=demo1,dc=freeipa,dc=org", "Secret123"
	URL        = "ldaps://ipa.demo1.freeipa.org/"
	BaseDN     = "dc=demo1,dc=freeipa,dc=org"
)

var (
	opts = []ldap.Opt{}
)

/////////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func TestMain(m *testing.M) {
	// Get opts
	if url := os.Getenv("LDAP_URL"); url != "" {
		opts = append(opts, ldap.WithUrl(url), ldap.WithUser(os.Getenv("LDAP_USER")), ldap.WithPassword(os.Getenv("LDAP_PASSWORD")))
		if dn := os.Getenv("LDAP_BASE_DN"); dn != "" {
			opts = append(opts, ldap.WithBaseDN(dn))
		}
	} else {
		// Use FreeIPA instance
		opts = append(opts, ldap.WithUrl(URL), ldap.WithUser(User), ldap.WithPassword(Pass), ldap.WithBaseDN(BaseDN), ldap.WithSkipVerify())
	}
	exitCode := m.Run()
	os.Exit(exitCode)
}

func Test_Manager_001(t *testing.T) {
	assert := assert.New(t)

	// Create a new queue manager
	manager, err := ldap.NewManager(opts...)
	if !assert.NoError(err) {
		t.FailNow()
	}
	assert.NotNil(manager)

	// Cancellation context
	ctx, cancel := context.WithCancel(context.Background())

	// Run the manager in the background
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		assert.NoError(manager.Run(ctx))
	}()

	// Wait for the manager to start
	time.Sleep(time.Second)

	// Retrieve all objects
	objects, err := manager.List(ctx, schema.ObjectListRequest{})
	if !assert.NoError(err) {
		t.FailNow()
	}
	assert.NotZero(objects.Count)

	// Get each object
	for _, object := range objects.Body {
		object2, err := manager.Get(ctx, object.DN)
		if !assert.NoError(err) {
			t.FailNow()
		}
		assert.Equal(object, object2)
	}

	// Cancel the context, wait for the manager to stop
	cancel()
	wg.Wait()
}

func Test_Manager_002(t *testing.T) {
	assert := assert.New(t)

	// Create a new queue manager
	manager, err := ldap.NewManager(opts...)
	if !assert.NoError(err) {
		t.FailNow()
	}
	assert.NotNil(manager)

	// Cancellation context
	ctx, cancel := context.WithCancel(context.Background())

	// Run the manager in the background
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		assert.NoError(manager.Run(ctx))
	}()

	// Wait for the manager to start
	time.Sleep(time.Second)

	// Bind
	t.Log("Binding")
	_, err = manager.Bind(ctx, "uid=djt,ou=users,dc=mutablelogic,dc=com", "test")
	assert.ErrorIs(err, httpresponse.ErrNotAuthorized)

	// Cancel the context, wait for the manager to stop
	cancel()
	wg.Wait()
}

func Test_Manager_003(t *testing.T) {
	assert := assert.New(t)

	// Create a new queue manager
	manager, err := ldap.NewManager(opts...)
	if !assert.NoError(err) {
		t.FailNow()
	}
	assert.NotNil(manager)

	// Cancellation context
	ctx, cancel := context.WithCancel(context.Background())

	// Run the manager in the background
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		assert.NoError(manager.Run(ctx))
	}()

	// Wait for the manager to start
	time.Sleep(time.Second)

	// Object Classes
	_, err = manager.ListObjectClasses(ctx)
	if !assert.NoError(err) {
		t.FailNow()
	}

	// Attribute Types
	types, err := manager.ListAttributeTypes(ctx)
	if !assert.NoError(err) {
		t.FailNow()
	}

	t.Log(types)

	// Cancel the context, wait for the manager to stop
	cancel()
	wg.Wait()
}
