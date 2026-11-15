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
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	tracetest "go.opentelemetry.io/otel/sdk/trace/tracetest"
)

///////////////////////////////////////////////////////////////////////////////
// FAKE SERVER

const (
	testTokenID  = "ec2c1d46-6a4b-4751-a310-af9601317f2d"
	testSecret   = "C2IgxjjLF7qSshsbwe8JGcbM075YXw"
	testToken    = "0." + testTokenID + "." + testSecret + ":X8vbvA0bduihIDe/qrzIQQ=="
	testOrgID    = "11111111-2222-3333-4444-555555555555"
	testProjectA = "aaaaaaaa-0000-0000-0000-000000000001"
)

// fakeBitwarden is the identity and API servers, which encrypt the payload
// with the access token's key, and store secrets encrypted with the
// organization's key, as Bitwarden does
type fakeBitwarden struct {
	sync.Mutex
	*httptest.Server
	t         *testing.T
	orgKey    *key
	secrets   map[string]encryptedSecret
	logins    int
	expiresIn int
	reject    bool // reject the next API call with 401
	readOnly  bool // return 404 for writes, as Bitwarden does without write access
	nextID    int
}

func newFakeBitwarden(t *testing.T) *fakeBitwarden {
	orgKey, err := deriveShareableKey([]byte("organization-key"), "org", "")
	require.NoError(t, err)
	f := &fakeBitwarden{t: t, orgKey: orgKey, secrets: make(map[string]encryptedSecret), expiresIn: 3600}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /identity/connect/token", f.login)
	mux.HandleFunc("GET /api/organizations/{org}/secrets", f.list)
	mux.HandleFunc("POST /api/organizations/{org}/secrets", f.create)
	mux.HandleFunc("GET /api/secrets/{id}", f.get)
	mux.HandleFunc("PUT /api/secrets/{id}", f.update)
	mux.HandleFunc("POST /api/secrets/delete", f.delete)
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

// add adds a secret, as if it were created in Bitwarden
func (f *fakeBitwarden) add(k, value string, projects ...string) string {
	f.Lock()
	defer f.Unlock()
	f.nextID++
	id := fmt.Sprintf("00000000-0000-0000-0000-%012d", f.nextID)
	s := encryptedSecret{ID: id, Key: f.mustEncrypt(k), Value: f.mustEncrypt(value), Note: f.mustEncrypt("a note"), Revised: "2026-01-02T03:04:05.123456Z"}
	for _, project := range projects {
		s.Projects = append(s.Projects, struct {
			ID string `json:"id"`
		}{project})
	}
	f.secrets[id] = s
	return id
}

// value returns the decrypted value of the secret
func (f *fakeBitwarden) value(id string) (string, string, []string) {
	f.Lock()
	defer f.Unlock()
	s, err := decryptSecret(f.orgKey, ptr(f.secrets[id]))
	require.NoError(f.t, err)
	return s.Value, s.Note, s.ProjectIDs
}

func (f *fakeBitwarden) mustEncrypt(value string) string {
	encrypted, err := f.orgKey.encrypt([]byte(value))
	require.NoError(f.t, err)
	return encrypted
}

func (f *fakeBitwarden) login(w http.ResponseWriter, r *http.Request) {
	f.Lock()
	defer f.Unlock()
	if r.FormValue("grant_type") != "client_credentials" || r.FormValue("scope") != "api.secrets" || r.FormValue("client_id") != testTokenID || r.FormValue("client_secret") != testSecret {
		http.Error(w, `{"error":"invalid_client"}`, http.StatusBadRequest)
		return
	}
	f.logins++
	token, err := parseAccessToken(testToken)
	require.NoError(f.t, err)
	payload, err := json.Marshal(map[string]string{"encryptionKey": base64.StdEncoding.EncodeToString(f.orgKey.bytes())})
	require.NoError(f.t, err)
	encrypted, err := token.key.encrypt(payload)
	require.NoError(f.t, err)
	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"organization":"` + testOrgID + `"}`))
	json.NewEncoder(w).Encode(map[string]any{
		"access_token":      fmt.Sprintf("header.%s.%d", claims, f.logins),
		"expires_in":        f.expiresIn,
		"token_type":        "Bearer",
		"scope":             "api.secrets",
		"encrypted_payload": encrypted,
	})
}

// authorized checks the bearer token is the current one
func (f *fakeBitwarden) authorized(w http.ResponseWriter, r *http.Request) bool {
	if f.reject || r.Header.Get("Authorization") != fmt.Sprintf("Bearer header.%s.%d", base64.RawURLEncoding.EncodeToString([]byte(`{"organization":"`+testOrgID+`"}`)), f.logins) {
		f.reject = false
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}

func (f *fakeBitwarden) list(w http.ResponseWriter, r *http.Request) {
	f.Lock()
	defer f.Unlock()
	if !f.authorized(w, r) {
		return
	} else if r.PathValue("org") != testOrgID {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	var secrets []encryptedSecret
	for _, s := range f.secrets {
		secrets = append(secrets, encryptedSecret{ID: s.ID, Key: s.Key, Revised: s.Revised, Projects: s.Projects})
	}
	json.NewEncoder(w).Encode(map[string]any{"secrets": secrets})
}

func (f *fakeBitwarden) get(w http.ResponseWriter, r *http.Request) {
	f.Lock()
	defer f.Unlock()
	if !f.authorized(w, r) {
		return
	}
	s, exists := f.secrets[r.PathValue("id")]
	if !exists {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(s)
}

func (f *fakeBitwarden) create(w http.ResponseWriter, r *http.Request) {
	f.Lock()
	defer f.Unlock()
	if !f.authorized(w, r) {
		return
	} else if f.readOnly {
		http.Error(w, `{"object":"error","message":"Resource not found."}`, http.StatusNotFound)
		return
	}
	var request secretRequest
	require.NoError(f.t, json.NewDecoder(r.Body).Decode(&request))
	if len(request.ProjectIDs) == 0 {
		// Machine accounts can't create secrets outside a project
		http.Error(w, `{"message":"project required"}`, http.StatusBadRequest)
		return
	}
	f.nextID++
	id := fmt.Sprintf("00000000-0000-0000-0000-%012d", f.nextID)
	s := encryptedSecret{ID: id, Key: request.Key, Value: request.Value, Note: request.Note}
	for _, project := range request.ProjectIDs {
		s.Projects = append(s.Projects, struct {
			ID string `json:"id"`
		}{project})
	}
	f.secrets[id] = s
	json.NewEncoder(w).Encode(s)
}

func (f *fakeBitwarden) update(w http.ResponseWriter, r *http.Request) {
	f.Lock()
	defer f.Unlock()
	if !f.authorized(w, r) {
		return
	} else if f.readOnly {
		http.Error(w, `{"object":"error","message":"Resource not found."}`, http.StatusNotFound)
		return
	}
	id := r.PathValue("id")
	if _, exists := f.secrets[id]; !exists {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	var request secretRequest
	require.NoError(f.t, json.NewDecoder(r.Body).Decode(&request))
	require.NotNil(f.t, request.ValueChanged)
	s := encryptedSecret{ID: id, Key: request.Key, Value: request.Value, Note: request.Note}
	for _, project := range request.ProjectIDs {
		s.Projects = append(s.Projects, struct {
			ID string `json:"id"`
		}{project})
	}
	f.secrets[id] = s
	json.NewEncoder(w).Encode(s)
}

func (f *fakeBitwarden) delete(w http.ResponseWriter, r *http.Request) {
	f.Lock()
	defer f.Unlock()
	if !f.authorized(w, r) {
		return
	}
	var ids []string
	require.NoError(f.t, json.NewDecoder(r.Body).Decode(&ids))
	type result struct {
		ID    string `json:"id"`
		Error string `json:"error"`
	}
	var results []result
	for _, id := range ids {
		if _, exists := f.secrets[id]; !exists {
			results = append(results, result{id, "Secret not found."})
		} else if f.readOnly {
			results = append(results, result{id, "access denied"})
		} else {
			delete(f.secrets, id)
			results = append(results, result{id, ""})
		}
	}
	json.NewEncoder(w).Encode(map[string]any{"data": results})
}

func ptr[T any](v T) *T {
	return &v
}

// isolate clears the bws environment variables
func isolate(t *testing.T) {
	t.Setenv(envAccessToken, "")
	t.Setenv(envServerURL, "")
}

///////////////////////////////////////////////////////////////////////////////
// TESTS

func Test_New(t *testing.T) {
	t.Run("NoToken", func(t *testing.T) {
		isolate(t)
		_, err := New()
		assert.ErrorIs(t, err, auth.ErrBadParameter)
	})

	t.Run("Env", func(t *testing.T) {
		// The token and server are bws's environment variables
		isolate(t)
		t.Setenv(envAccessToken, testToken)
		t.Setenv(envServerURL, "https://vault.example.com/")
		mgr, err := New()
		require.NoError(t, err)
		assert.Equal(t, testTokenID, mgr.client.token.id)
		assert.Equal(t, "https://vault.example.com/api", mgr.client.apiURL)
		assert.Equal(t, "https://vault.example.com/identity", mgr.client.identityURL)
	})

	t.Run("Defaults", func(t *testing.T) {
		isolate(t)
		mgr, err := New(WithAccessToken(testToken))
		require.NoError(t, err)
		assert.Equal(t, "https://api.bitwarden.com", mgr.client.apiURL)
		assert.Equal(t, "https://identity.bitwarden.com", mgr.client.identityURL)
	})

	t.Run("Options", func(t *testing.T) {
		// Options are used in place of the environment
		isolate(t)
		t.Setenv(envServerURL, "https://vault.example.com")
		mgr, err := New(WithAccessToken(testToken), WithURLs("https://api.bitwarden.eu", "https://identity.bitwarden.eu"))
		require.NoError(t, err)
		assert.Equal(t, "https://api.bitwarden.eu", mgr.client.apiURL)
		assert.Equal(t, "https://identity.bitwarden.eu", mgr.client.identityURL)
	})

	t.Run("Invalid", func(t *testing.T) {
		isolate(t)
		for _, opt := range []Opt{WithAccessToken(""), WithAccessToken("not a token"), WithServerURL("vault.example.com"), WithURLs("https://api", "ftp://identity"), WithProject("project"), WithHTTPClient(nil)} {
			_, err := New(WithAccessToken(testToken), opt)
			assert.ErrorIs(t, err, auth.ErrBadParameter)
		}
	})
}

func Test_SetGet(t *testing.T) {
	isolate(t)
	ctx := context.Background()
	f := newFakeBitwarden(t)
	mgr, err := New(WithAccessToken(testToken), WithServerURL(f.URL), WithProject(testProjectA))
	require.NoError(t, err)

	t.Run("Get", func(t *testing.T) {
		f.add("plain", "hunter2")
		f.add("object", `{"user":"admin"}`)
		got, err := mgr.Get(ctx, "plain")
		require.NoError(t, err)
		assert.Equal(t, json.RawMessage(`"hunter2"`), got)
		got, err = mgr.Get(ctx, "object")
		require.NoError(t, err)
		assert.JSONEq(t, `{"user":"admin"}`, string(got))
		assert.Equal(t, 1, f.logins, "the session is reused")
	})

	t.Run("Create", func(t *testing.T) {
		// A string is stored without its quotes, in the project
		require.NoError(t, mgr.Set(ctx, "created", json.RawMessage(`"secret"`)))
		got, err := mgr.Get(ctx, "created")
		require.NoError(t, err)
		assert.Equal(t, json.RawMessage(`"secret"`), got)
		index, err := mgr.index(ctx)
		require.NoError(t, err)
		value, _, projects := f.value(index["created"][0])
		assert.Equal(t, "secret", value)
		assert.Equal(t, []string{testProjectA}, projects)
	})

	t.Run("Update", func(t *testing.T) {
		// The note and projects are kept
		id := f.add("updated", "one", testProjectA)
		require.NoError(t, mgr.Set(ctx, "updated", json.RawMessage(`{"a":1}`)))
		value, note, projects := f.value(id)
		assert.Equal(t, `{"a":1}`, value)
		assert.Equal(t, "a note", note)
		assert.Equal(t, []string{testProjectA}, projects)
	})

	t.Run("NoProject", func(t *testing.T) {
		// Without a project, Bitwarden refuses to create the secret
		noProject, err := New(WithAccessToken(testToken), WithServerURL(f.URL))
		require.NoError(t, err)
		assert.ErrorIs(t, noProject.Set(ctx, "orphan", json.RawMessage(`"x"`)), auth.ErrBadParameter)
	})

	t.Run("ReadOnly", func(t *testing.T) {
		// Bitwarden returns 404 for a write without write access, which is
		// forbidden, for a new secret or an existing one
		f.add("readonly", "one", testProjectA)
		f.readOnly = true
		defer func() { f.readOnly = false }()
		assert.ErrorIs(t, mgr.Set(ctx, "readonly_new", json.RawMessage(`"x"`)), auth.ErrForbidden)
		assert.ErrorIs(t, mgr.Set(ctx, "readonly", json.RawMessage(`"x"`)), auth.ErrForbidden)
	})

	t.Run("Duplicate", func(t *testing.T) {
		f.add("twice", "one")
		f.add("twice", "two")
		_, err := mgr.Get(ctx, "twice")
		assert.ErrorIs(t, err, auth.ErrConflict)
		assert.ErrorIs(t, mgr.Set(ctx, "twice", json.RawMessage(`"x"`)), auth.ErrConflict)
	})

	t.Run("NotFound", func(t *testing.T) {
		_, err := mgr.Get(ctx, "missing")
		assert.ErrorIs(t, err, auth.ErrNotFound)
	})

	t.Run("InvalidKey", func(t *testing.T) {
		for _, key := range []string{"", "a/b", "1abc"} {
			_, err := mgr.Get(ctx, key)
			assert.ErrorIs(t, err, auth.ErrBadParameter, key)
			assert.ErrorIs(t, mgr.Set(ctx, key, json.RawMessage(`"x"`)), auth.ErrBadParameter, key)
		}
		assert.ErrorIs(t, mgr.Set(ctx, "valid", json.RawMessage(`not json`)), auth.ErrBadParameter)
	})
}

func Test_List(t *testing.T) {
	isolate(t)
	ctx := context.Background()
	f := newFakeBitwarden(t)
	mgr, err := New(WithAccessToken(testToken), WithServerURL(f.URL), WithEnv())
	require.NoError(t, err)
	t.Setenv("GOAUTH_TEST_LIST_ENV", "from-env")

	// Empty, and the environment isn't listed
	list, err := mgr.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, list)

	// In key order, with a duplicate key listed twice, and keys which
	// aren't valid not listed
	f.add("zeta", "z")
	f.add("alpha", "a")
	f.add("zeta", "z2")
	f.add("not a key", "x")
	list, err = mgr.List(ctx)
	require.NoError(t, err)
	var keys []string
	for _, c := range list {
		keys = append(keys, c.Key)
	}
	assert.Equal(t, []string{"alpha", "zeta", "zeta"}, keys)
	assert.Equal(t, "2026-01-02T03:04:05.123456Z", list[0].UpdatedAt.Format(time.RFC3339Nano))
}

func Test_Delete(t *testing.T) {
	isolate(t)
	ctx := context.Background()
	f := newFakeBitwarden(t)
	mgr, err := New(WithAccessToken(testToken), WithServerURL(f.URL))
	require.NoError(t, err)

	id := f.add("key", "value")
	require.NoError(t, mgr.Delete(ctx, "key"))
	assert.NotContains(t, f.secrets, id)
	assert.ErrorIs(t, mgr.Delete(ctx, "key"), auth.ErrNotFound)
	assert.ErrorIs(t, mgr.Delete(ctx, "a/b"), auth.ErrBadParameter)

	// More than one secret with the key isn't deleted
	f.add("twice", "one")
	f.add("twice", "two")
	assert.ErrorIs(t, mgr.Delete(ctx, "twice"), auth.ErrConflict)

	// Without write access, it's forbidden
	f.add("readonly", "one")
	f.readOnly = true
	defer func() { f.readOnly = false }()
	assert.ErrorIs(t, mgr.Delete(ctx, "readonly"), auth.ErrForbidden)
}

func Test_Session(t *testing.T) {
	isolate(t)
	ctx := context.Background()
	f := newFakeBitwarden(t)
	f.add("key", "value")

	t.Run("Expired", func(t *testing.T) {
		// A token which has expired is replaced, on each call
		f.expiresIn = 0
		mgr, err := New(WithAccessToken(testToken), WithServerURL(f.URL))
		require.NoError(t, err)
		logins := f.logins
		_, err = mgr.Get(ctx, "key")
		require.NoError(t, err)
		assert.Greater(t, f.logins, logins+1)
		f.expiresIn = 3600
	})

	t.Run("Short", func(t *testing.T) {
		// A token which expires within a minute is still used, until
		// halfway through its life
		f.expiresIn = 30
		mgr, err := New(WithAccessToken(testToken), WithServerURL(f.URL))
		require.NoError(t, err)
		logins := f.logins
		_, err = mgr.Get(ctx, "key")
		require.NoError(t, err)
		_, err = mgr.Get(ctx, "key")
		require.NoError(t, err)
		assert.Equal(t, logins+1, f.logins)
		f.expiresIn = 3600
	})

	t.Run("Rejected", func(t *testing.T) {
		// A token which is rejected is replaced, and the call retried
		mgr, err := New(WithAccessToken(testToken), WithServerURL(f.URL))
		require.NoError(t, err)
		_, err = mgr.Get(ctx, "key")
		require.NoError(t, err)
		logins := f.logins
		f.reject = true
		got, err := mgr.Get(ctx, "key")
		require.NoError(t, err)
		assert.Equal(t, json.RawMessage(`"value"`), got)
		assert.Equal(t, logins+1, f.logins)
	})

	t.Run("InvalidClient", func(t *testing.T) {
		other := strings.Replace(testToken, testSecret, "wrong", 1)
		mgr, err := New(WithAccessToken(other), WithServerURL(f.URL))
		require.NoError(t, err)
		_, err = mgr.Get(ctx, "key")
		assert.ErrorIs(t, err, auth.ErrForbidden)
	})

	t.Run("Unavailable", func(t *testing.T) {
		mgr, err := New(WithAccessToken(testToken), WithServerURL("http://127.0.0.1:1"))
		require.NoError(t, err)
		_, err = mgr.Get(ctx, "key")
		assert.ErrorIs(t, err, auth.ErrServiceUnavailable)
	})
}

func Test_Expand(t *testing.T) {
	isolate(t)
	ctx := context.Background()
	f := newFakeBitwarden(t)
	f.add("user", "admin")
	f.add("quoted", `"secret"`)
	f.add("object", `{"a":1}`)
	mgr, err := New(WithAccessToken(testToken), WithServerURL(f.URL))
	require.NoError(t, err)

	got, err := mgr.Expand(ctx, "$user:${quoted}@host/$user")
	require.NoError(t, err)
	assert.Equal(t, "admin:secret@host/admin", got)

	// No placeholders don't log in
	logins := f.logins
	got, err = mgr.Expand(ctx, "no placeholders")
	require.NoError(t, err)
	assert.Equal(t, "no placeholders", got)
	assert.Equal(t, logins, f.logins)

	_, err = mgr.Expand(ctx, "$missing")
	assert.ErrorIs(t, err, auth.ErrNotFound)
	_, err = mgr.Expand(ctx, "$object")
	assert.ErrorIs(t, err, auth.ErrBadParameter)
}

func Test_WithEnv(t *testing.T) {
	isolate(t)
	ctx := context.Background()
	t.Setenv("GOAUTH_TEST_ENV_ONLY", "from-env")
	t.Setenv("GOAUTH_TEST_ENV_NUMBER", "123")
	t.Setenv("GOAUTH_TEST_STORED", "from-env")
	f := newFakeBitwarden(t)
	f.add("GOAUTH_TEST_STORED", "from-bitwarden")

	recorder := tracetest.NewSpanRecorder()
	tracer := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder)).Tracer("test")
	mgr, err := New(WithEnv(), WithAccessToken(testToken), WithServerURL(f.URL), WithTracer(tracer))
	require.NoError(t, err)

	got, err := mgr.Get(ctx, "GOAUTH_TEST_STORED")
	require.NoError(t, err)
	assert.Equal(t, json.RawMessage(`"from-bitwarden"`), got)
	got, err = mgr.Get(ctx, "GOAUTH_TEST_ENV_ONLY")
	require.NoError(t, err)
	assert.Equal(t, json.RawMessage(`"from-env"`), got)
	_, err = mgr.Get(ctx, "GOAUTH_TEST_MISSING")
	assert.ErrorIs(t, err, auth.ErrNotFound)

	expanded, err := mgr.Expand(ctx, "$GOAUTH_TEST_STORED ${GOAUTH_TEST_ENV_ONLY} $GOAUTH_TEST_ENV_NUMBER")
	require.NoError(t, err)
	assert.Equal(t, "from-bitwarden from-env 123", expanded)

	// Every method is traced, without the secrets or the access token
	spans := make(map[string]sdktrace.ReadOnlySpan)
	for _, span := range recorder.Ended() {
		spans[span.Name()] = span
		for _, attr := range span.Attributes() {
			for _, secret := range []string{"from-bitwarden", "from-env", testSecret} {
				assert.NotContains(t, attr.Value.Emit(), secret, span.Name())
			}
		}
	}
	for _, name := range []string{"credential.bitwarden.New", "credential.bitwarden.Get", "credential.bitwarden.Expand", "credential.env.Get", "credential.env.Expand"} {
		assert.Contains(t, spans, name)
	}
	assert.Equal(t, spans["credential.bitwarden.Expand"].SpanContext().SpanID(), spans["credential.env.Expand"].Parent().SpanID())
}
