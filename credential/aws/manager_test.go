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

package aws

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	// Packages
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	secretsmanager "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	smithy "github.com/aws/smithy-go"
	auth "github.com/mutablelogic/go-auth"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	tracetest "go.opentelemetry.io/otel/sdk/trace/tracetest"
)

///////////////////////////////////////////////////////////////////////////////
// FAKE CLIENT

// fakeClient is an in-memory Secrets Manager, which returns the SDK's errors
type fakeClient struct {
	sync.Mutex
	secrets map[string]*string // nil is a binary secret
	kms     map[string]string
	desc    map[string]string
	reads   int
	deleted []*secretsmanager.DeleteSecretInput
	err     error // returned by every call, when set
}

func newFakeClient() *fakeClient {
	return &fakeClient{secrets: make(map[string]*string), kms: make(map[string]string), desc: make(map[string]string)}
}

func (c *fakeClient) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	c.Lock()
	defer c.Unlock()
	c.reads++
	if c.err != nil {
		return nil, c.err
	}
	value, exists := c.secrets[*in.SecretId]
	if !exists {
		return nil, &smtypes.ResourceNotFoundException{Message: awssdk.String("not found")}
	}
	output := &secretsmanager.GetSecretValueOutput{Name: in.SecretId, SecretString: value}
	if value == nil {
		output.SecretBinary = []byte{1, 2, 3}
	}
	return output, nil
}

func (c *fakeClient) PutSecretValue(_ context.Context, in *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	c.Lock()
	defer c.Unlock()
	if c.err != nil {
		return nil, c.err
	}
	if _, exists := c.secrets[*in.SecretId]; !exists {
		return nil, &smtypes.ResourceNotFoundException{Message: awssdk.String("not found")}
	}
	c.secrets[*in.SecretId] = in.SecretString
	return &secretsmanager.PutSecretValueOutput{Name: in.SecretId}, nil
}

func (c *fakeClient) CreateSecret(_ context.Context, in *secretsmanager.CreateSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
	c.Lock()
	defer c.Unlock()
	if c.err != nil {
		return nil, c.err
	}
	if _, exists := c.secrets[*in.Name]; exists {
		return nil, &smtypes.ResourceExistsException{Message: awssdk.String("exists")}
	}
	c.secrets[*in.Name] = in.SecretString
	if in.KmsKeyId != nil {
		c.kms[*in.Name] = *in.KmsKeyId
	}
	return &secretsmanager.CreateSecretOutput{Name: in.Name}, nil
}

// ListSecrets returns two secrets a page, filtered by a name prefix, which
// isn't case-sensitive, as in AWS
func (c *fakeClient) ListSecrets(_ context.Context, in *secretsmanager.ListSecretsInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	c.Lock()
	defer c.Unlock()
	if c.err != nil {
		return nil, c.err
	}
	var names []string
	for name := range c.secrets {
		match := true
		for _, filter := range in.Filters {
			if filter.Key == smtypes.FilterNameStringTypeName {
				match = strings.HasPrefix(strings.ToLower(name), strings.ToLower(filter.Values[0]))
			}
		}
		if match {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	start, _ := strconv.Atoi(awssdk.ToString(in.NextToken))
	output := &secretsmanager.ListSecretsOutput{}
	for i := start; i < len(names) && i < start+2; i++ {
		changed := time.Date(2026, 1, 1, 0, 0, i, 0, time.UTC)
		entry := smtypes.SecretListEntry{Name: awssdk.String(names[i]), LastChangedDate: &changed}
		if description, ok := c.desc[names[i]]; ok {
			entry.Description = awssdk.String(description)
		}
		output.SecretList = append(output.SecretList, entry)
	}
	if start+2 < len(names) {
		output.NextToken = awssdk.String(strconv.Itoa(start + 2))
	}
	return output, nil
}

func (c *fakeClient) DeleteSecret(_ context.Context, in *secretsmanager.DeleteSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.DeleteSecretOutput, error) {
	c.Lock()
	defer c.Unlock()
	if c.err != nil {
		return nil, c.err
	}
	if _, exists := c.secrets[*in.SecretId]; !exists {
		return nil, &smtypes.ResourceNotFoundException{Message: awssdk.String("not found")}
	}
	delete(c.secrets, *in.SecretId)
	c.deleted = append(c.deleted, in)
	return &secretsmanager.DeleteSecretOutput{Name: in.SecretId}, nil
}

func (c *fakeClient) UpdateSecret(_ context.Context, in *secretsmanager.UpdateSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.UpdateSecretOutput, error) {
	c.Lock()
	defer c.Unlock()
	if c.err != nil {
		return nil, c.err
	}
	if _, exists := c.secrets[*in.SecretId]; !exists {
		return nil, &smtypes.ResourceNotFoundException{Message: awssdk.String("not found")}
	}
	if in.Description != nil {
		c.desc[*in.SecretId] = *in.Description
	}
	return &secretsmanager.UpdateSecretOutput{Name: in.SecretId}, nil
}

// racingClient creates the secret just before CreateSecret, as if another
// writer did
type racingClient struct {
	*fakeClient
}

func (c racingClient) CreateSecret(ctx context.Context, in *secretsmanager.CreateSecretInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
	c.Lock()
	c.secrets[*in.Name] = awssdk.String(`"theirs"`)
	c.Unlock()
	return c.fakeClient.CreateSecret(ctx, in, opts...)
}

///////////////////////////////////////////////////////////////////////////////
// TESTS

// isolate clears the AWS environment, so tests don't use the user's
// configuration or credentials
func isolate(t *testing.T) {
	t.Helper()
	for _, key := range []string{"AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_SECRETS_MANAGER"} {
		t.Setenv(key, "")
	}
	none := filepath.Join(t.TempDir(), "none")
	t.Setenv("AWS_CONFIG_FILE", none)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", none)
}

func Test_New(t *testing.T) {
	ctx := context.Background()

	t.Run("NoRegion", func(t *testing.T) {
		isolate(t)
		_, err := New(ctx)
		assert.ErrorIs(t, err, auth.ErrBadParameter)
	})

	t.Run("EnvRegion", func(t *testing.T) {
		// The region and credentials are from AWS's environment variables
		isolate(t)
		t.Setenv("AWS_REGION", "eu-west-1")
		t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
		mgr, err := New(ctx)
		require.NoError(t, err)
		assert.IsType(t, &secretsmanager.Client{}, mgr.client)
		assert.Equal(t, "eu-west-1", mgr.client.(*secretsmanager.Client).Options().Region)
	})

	t.Run("Options", func(t *testing.T) {
		// Options are used in place of the environment
		isolate(t)
		t.Setenv("AWS_REGION", "eu-west-1")
		mgr, err := New(ctx, WithRegion("us-east-2"), WithCredentials("AKIDEXAMPLE", "secret", ""), WithEndpoint("http://localhost:4566"))
		require.NoError(t, err)
		options := mgr.client.(*secretsmanager.Client).Options()
		assert.Equal(t, "us-east-2", options.Region)
		require.NotNil(t, options.BaseEndpoint)
		assert.Equal(t, "http://localhost:4566", *options.BaseEndpoint)
		creds, err := options.Credentials.Retrieve(ctx)
		require.NoError(t, err)
		assert.Equal(t, "AKIDEXAMPLE", creds.AccessKeyID)
	})

	t.Run("InvalidOptions", func(t *testing.T) {
		for _, opt := range []Opt{WithRegion(""), WithProfile(""), WithCredentials("", "secret", ""), WithEndpoint(""), WithKMSKey(""), WithPrefix("bad prefix")} {
			_, err := New(ctx, withClient(newFakeClient()), opt)
			assert.ErrorIs(t, err, auth.ErrBadParameter)
		}
	})
}

func Test_SetGet(t *testing.T) {
	ctx := context.Background()
	fake := newFakeClient()
	mgr, err := New(ctx, withClient(fake), WithPrefix("app/"), WithKMSKey("alias/app"))
	require.NoError(t, err)

	t.Run("Create", func(t *testing.T) {
		// A new secret is created, with the prefix and the KMS key
		require.NoError(t, mgr.Set(ctx, "token", json.RawMessage(`{"a":1}`)))
		require.Contains(t, fake.secrets, "app/token")
		assert.Equal(t, `{"a":1}`, *fake.secrets["app/token"])
		assert.Equal(t, "alias/app", fake.kms["app/token"])
		got, err := mgr.Get(ctx, "token")
		require.NoError(t, err)
		assert.JSONEq(t, `{"a":1}`, string(got))
	})

	t.Run("Replace", func(t *testing.T) {
		require.NoError(t, mgr.Set(ctx, "token", json.RawMessage(`"two"`)))
		got, err := mgr.Get(ctx, "token")
		require.NoError(t, err)
		assert.Equal(t, json.RawMessage(`"two"`), got)
	})

	t.Run("Race", func(t *testing.T) {
		// When another writer creates the secret first, a version is added
		raced, err := New(ctx, withClient(racingClient{fake}))
		require.NoError(t, err)
		require.NoError(t, raced.Set(ctx, "raced", json.RawMessage(`"mine"`)))
		assert.Equal(t, `"mine"`, *fake.secrets["raced"])
	})

	t.Run("PlainText", func(t *testing.T) {
		// A secret created outside, which isn't JSON, is a JSON string
		fake.secrets["app/plain"] = awssdk.String("not json")
		got, err := mgr.Get(ctx, "plain")
		require.NoError(t, err)
		assert.Equal(t, json.RawMessage(`"not json"`), got)
	})

	t.Run("Binary", func(t *testing.T) {
		fake.secrets["app/binary"] = nil
		_, err := mgr.Get(ctx, "binary")
		assert.ErrorIs(t, err, auth.ErrBadParameter)
	})

	t.Run("NotFound", func(t *testing.T) {
		_, err := mgr.Get(ctx, "missing")
		assert.ErrorIs(t, err, auth.ErrNotFound)
		var notFound *smtypes.ResourceNotFoundException
		assert.ErrorAs(t, err, &notFound, "the AWS error is wrapped")
	})

	t.Run("InvalidKey", func(t *testing.T) {
		for _, key := range []string{"", "a/b", "../x", "1abc"} {
			_, err := mgr.Get(ctx, key)
			assert.ErrorIs(t, err, auth.ErrBadParameter, "key %q", key)
			assert.ErrorIs(t, mgr.Set(ctx, key, json.RawMessage(`"x"`)), auth.ErrBadParameter, "key %q", key)
		}
	})

	t.Run("NotJSON", func(t *testing.T) {
		assert.ErrorIs(t, mgr.Set(ctx, "token", json.RawMessage(`not json`)), auth.ErrBadParameter)
	})
}

func Test_List(t *testing.T) {
	ctx := context.Background()
	fake := newFakeClient()
	for _, name := range []string{"app/zeta", "app/alpha", "app/beta", "APP/upper", "app/not a key", "other/gamma"} {
		fake.secrets[name] = awssdk.String(`"x"`)
	}

	t.Run("Prefix", func(t *testing.T) {
		// Secrets with the prefix, over several pages, in key order, and not
		// those whose prefix only matches without case, or aren't keys
		mgr, err := New(ctx, withClient(fake), WithPrefix("app/"))
		require.NoError(t, err)
		list, err := mgr.List(ctx)
		require.NoError(t, err)
		var keys []string
		for _, c := range list {
			keys = append(keys, c.Key)
			assert.False(t, c.UpdatedAt.IsZero())
		}
		assert.Equal(t, []string{"alpha", "beta", "zeta"}, keys)
	})

	t.Run("NoPrefix", func(t *testing.T) {
		// Names with a "/" aren't keys, so without a prefix, only plain
		// names are listed
		fake.secrets["plain"] = awssdk.String(`"x"`)
		mgr, err := New(ctx, withClient(fake))
		require.NoError(t, err)
		list, err := mgr.List(ctx)
		require.NoError(t, err)
		require.Len(t, list, 1)
		assert.Equal(t, "plain", list[0].Key)
	})

	t.Run("Error", func(t *testing.T) {
		failing := newFakeClient()
		failing.err = &smithy.GenericAPIError{Code: "AccessDeniedException"}
		mgr, err := New(ctx, withClient(failing))
		require.NoError(t, err)
		_, err = mgr.List(ctx)
		assert.ErrorIs(t, err, auth.ErrForbidden)
	})
}

func Test_Delete(t *testing.T) {
	ctx := context.Background()
	for name, test := range map[string]struct {
		opts     []Opt
		force    bool
		recovery int64
	}{
		"Default":  {},
		"Force":    {opts: []Opt{WithRecoveryWindow(0)}, force: true},
		"Recovery": {opts: []Opt{WithRecoveryWindow(7)}, recovery: 7},
	} {
		t.Run(name, func(t *testing.T) {
			fake := newFakeClient()
			fake.secrets["app/key"] = awssdk.String(`"x"`)
			mgr, err := New(ctx, append([]Opt{withClient(fake), WithPrefix("app/")}, test.opts...)...)
			require.NoError(t, err)
			require.NoError(t, mgr.Delete(ctx, "key"))
			require.Len(t, fake.deleted, 1)
			assert.Equal(t, "app/key", *fake.deleted[0].SecretId)
			assert.Equal(t, test.force, awssdk.ToBool(fake.deleted[0].ForceDeleteWithoutRecovery))
			assert.Equal(t, test.recovery, awssdk.ToInt64(fake.deleted[0].RecoveryWindowInDays))
			assert.ErrorIs(t, mgr.Delete(ctx, "key"), auth.ErrNotFound)
			assert.ErrorIs(t, mgr.Delete(ctx, "a/b"), auth.ErrBadParameter)
		})
	}

	t.Run("InvalidWindow", func(t *testing.T) {
		for _, days := range []int{-1, 6, 31} {
			_, err := New(ctx, withClient(newFakeClient()), WithRecoveryWindow(days))
			assert.ErrorIs(t, err, auth.ErrBadParameter, days)
		}
	})
}

func Test_Describe(t *testing.T) {
	ctx := context.Background()
	fake := newFakeClient()
	fake.secrets["app/key"] = awssdk.String(`"x"`)
	mgr, err := New(ctx, withClient(fake), WithPrefix("app/"))
	require.NoError(t, err)

	// The description is kept beside the secret, and listed
	require.NoError(t, mgr.Describe(ctx, "key", "  The API key  "))
	assert.Equal(t, "The API key", fake.desc["app/key"])
	assert.Equal(t, `"x"`, *fake.secrets["app/key"], "the value isn't changed")
	list, err := mgr.List(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "The API key", list[0].Description)

	// An empty description removes it
	require.NoError(t, mgr.Describe(ctx, "key", ""))
	list, err = mgr.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, list[0].Description)

	assert.ErrorIs(t, mgr.Describe(ctx, "missing", "x"), auth.ErrNotFound)
	assert.ErrorIs(t, mgr.Describe(ctx, "a/b", "x"), auth.ErrBadParameter)
}

func Test_Errors(t *testing.T) {
	ctx := context.Background()
	for name, test := range map[string]struct {
		err  error
		want auth.Err
	}{
		"AccessDenied":   {&smithy.GenericAPIError{Code: "AccessDeniedException"}, auth.ErrForbidden},
		"ExpiredToken":   {&smithy.GenericAPIError{Code: "ExpiredTokenException"}, auth.ErrForbidden},
		"Decryption":     {&smtypes.DecryptionFailure{}, auth.ErrForbidden},
		"InvalidRequest": {&smtypes.InvalidRequestException{}, auth.ErrBadParameter},
		"Throttled":      {&smithy.GenericAPIError{Code: "ThrottlingException"}, auth.ErrServiceUnavailable},
		"InternalError":  {&smtypes.InternalServiceError{}, auth.ErrServiceUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			fake := newFakeClient()
			fake.err = test.err
			mgr, err := New(ctx, withClient(fake))
			require.NoError(t, err)
			_, err = mgr.Get(ctx, "key")
			assert.ErrorIs(t, err, test.want)
			assert.ErrorIs(t, mgr.Set(ctx, "key", json.RawMessage(`"x"`)), test.want)
		})
	}
}

func Test_Expand(t *testing.T) {
	ctx := context.Background()
	fake := newFakeClient()
	mgr, err := New(ctx, withClient(fake))
	require.NoError(t, err)
	fake.secrets["user"] = awssdk.String(`"admin"`)
	fake.secrets["plain"] = awssdk.String(`hunter2`)
	fake.secrets["object"] = awssdk.String(`{"a":1}`)

	// Each secret is read once, however many times it's used
	got, err := mgr.Expand(ctx, "$user:${plain}@host/$user")
	require.NoError(t, err)
	assert.Equal(t, "admin:hunter2@host/admin", got)
	assert.Equal(t, 2, fake.reads)

	_, err = mgr.Expand(ctx, "$missing")
	assert.ErrorIs(t, err, auth.ErrNotFound)
	_, err = mgr.Expand(ctx, "$object")
	assert.ErrorIs(t, err, auth.ErrBadParameter)
}

func Test_WithEnv(t *testing.T) {
	ctx := context.Background()
	t.Setenv("GOAUTH_TEST_ENV_ONLY", "from-env")
	t.Setenv("GOAUTH_TEST_ENV_NUMBER", "123")
	t.Setenv("GOAUTH_TEST_STORED", "from-env")
	fake := newFakeClient()
	fake.secrets["GOAUTH_TEST_STORED"] = awssdk.String(`"from-aws"`)

	recorder := tracetest.NewSpanRecorder()
	tracer := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder)).Tracer("test")
	mgr, err := New(ctx, withClient(fake), WithEnv(), WithTracer(tracer))
	require.NoError(t, err)

	got, err := mgr.Get(ctx, "GOAUTH_TEST_STORED")
	require.NoError(t, err)
	assert.Equal(t, json.RawMessage(`"from-aws"`), got)
	got, err = mgr.Get(ctx, "GOAUTH_TEST_ENV_ONLY")
	require.NoError(t, err)
	assert.Equal(t, json.RawMessage(`"from-env"`), got)
	_, err = mgr.Get(ctx, "GOAUTH_TEST_MISSING")
	assert.ErrorIs(t, err, auth.ErrNotFound)

	expanded, err := mgr.Expand(ctx, "$GOAUTH_TEST_STORED ${GOAUTH_TEST_ENV_ONLY} $GOAUTH_TEST_ENV_NUMBER")
	require.NoError(t, err)
	assert.Equal(t, "from-aws from-env 123", expanded)

	// Every method is traced, without the secrets, and the environment's
	// spans are inside the manager's
	spans := make(map[string]sdktrace.ReadOnlySpan)
	for _, span := range recorder.Ended() {
		spans[span.Name()] = span
		for _, attr := range span.Attributes() {
			assert.NotContains(t, attr.Value.Emit(), "from-aws", span.Name())
			assert.NotContains(t, attr.Value.Emit(), "from-env", span.Name())
		}
	}
	for _, name := range []string{"credential.aws.New", "credential.aws.Get", "credential.aws.Expand", "credential.env.Get", "credential.env.Expand"} {
		assert.Contains(t, spans, name)
	}
	assert.Equal(t, spans["credential.aws.Expand"].SpanContext().SpanID(), spans["credential.env.Expand"].Parent().SpanID())
}
