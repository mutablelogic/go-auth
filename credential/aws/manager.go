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
	"errors"
	"maps"
	"os"
	"slices"
	"strings"

	// Packages
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	secretsmanager "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	smithy "github.com/aws/smithy-go"
	auth "github.com/mutablelogic/go-auth"
	credential "github.com/mutablelogic/go-auth/credential"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	types "github.com/mutablelogic/go-server/pkg/types"
	attribute "go.opentelemetry.io/otel/attribute"
	trace "go.opentelemetry.io/otel/trace"
)

////////////////////////////////////////////////////////////////////////////////
// TYPES

// Manager stores credentials as secrets in AWS Secrets Manager, one for each
// key, which AWS encrypts with KMS
type Manager struct {
	opt
}

// client is the part of the Secrets Manager client which the manager uses
type client interface {
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	PutSecretValue(context.Context, *secretsmanager.PutSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error)
	CreateSecret(context.Context, *secretsmanager.CreateSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error)
	ListSecrets(context.Context, *secretsmanager.ListSecretsInput, ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error)
	DeleteSecret(context.Context, *secretsmanager.DeleteSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.DeleteSecretOutput, error)
	UpdateSecret(context.Context, *secretsmanager.UpdateSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.UpdateSecretOutput, error)
}

var _ credential.CredentialProvider = (*Manager)(nil)
var _ credential.CredentialManager = (*Manager)(nil)
var _ client = (*secretsmanager.Client)(nil)

////////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// New returns a manager for credentials in AWS Secrets Manager. The region,
// credentials and endpoint are from the AWS environment variables, such as
// AWS_REGION, AWS_PROFILE, AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, and
// the shared configuration files, unless they are set with options.
func New(ctx context.Context, opts ...Opt) (_ *Manager, err error) {
	self := new(Manager)
	if err := self.opt.apply(opts); err != nil {
		return nil, err
	}

	// Trace creating the manager, which needs the tracer from the options
	ctx, endSpan := otel.StartSpan(self.tracer, ctx, "credential.aws.New",
		attribute.String("prefix", self.prefix),
	)
	defer func() { endSpan(err) }()

	// Create the client from the AWS configuration
	if self.client == nil {
		config, err := awsconfig.LoadDefaultConfig(ctx, self.config...)
		if err != nil {
			return nil, auth.ErrBadParameter.Withf("aws configuration: %w", err)
		} else if config.Region == "" {
			return nil, auth.ErrBadParameter.With("aws region is required, from AWS_REGION, the profile, or WithRegion")
		}
		self.client = secretsmanager.NewFromConfig(config)
	}

	// Return success
	return self, nil
}

////////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Expand replaces each $KEY or ${KEY} placeholder in the value with the
// credential for the key, which must be a string, or with the environment
// variable, with WithEnv, when there is no secret for it. Keys containing
// "-" must use the ${KEY} form. Each secret is read once, however many times
// it's used. Returns an error, rather than a partly expanded value, if a
// placeholder is not a valid key, or its credential does not exist or is not
// a string.
func (self *Manager) Expand(ctx context.Context, value string) (_ string, err error) {
	// The value isn't recorded, as it may contain secrets, only the keys of
	// the credentials used
	ctx, endSpan := otel.StartSpan(self.tracer, ctx, "credential.aws.Expand")
	defer func() { endSpan(err) }()

	var result error
	cache := make(map[string]string)
	defer func() {
		trace.SpanFromContext(ctx).SetAttributes(attribute.StringSlice("keys", slices.Sorted(maps.Keys(cache))))
	}()
	expanded := os.Expand(value, func(name string) string {
		if result != nil {
			return ""
		} else if value, exists := cache[name]; exists {
			return value
		} else if value, err := self.lookup(ctx, name); err != nil {
			result = err
			return ""
		} else {
			cache[name] = value
			return value
		}
	})
	if result != nil {
		return "", result
	}
	return expanded, nil
}

// Get returns the credential for the key, as JSON, or the environment
// variable's value, with WithEnv, when there is no secret for it. A secret
// which isn't JSON is returned as a JSON string. Returns an error if the key
// isn't valid, or the credential doesn't exist.
func (self *Manager) Get(ctx context.Context, key string) (_ json.RawMessage, err error) {
	ctx, endSpan := otel.StartSpan(self.tracer, ctx, "credential.aws.Get",
		attribute.String("key", key),
	)
	defer func() { endSpan(err) }()

	if err := validateKey(key); err != nil {
		return nil, err
	}
	value, err := self.read(ctx, key)
	if errors.Is(err, auth.ErrNotFound) && self.env != nil {
		return self.env.Get(ctx, key)
	} else if err != nil {
		return nil, err
	}
	if json.Valid([]byte(value)) {
		return json.RawMessage(value), nil
	}
	return json.Marshal(value)
}

// Set stores the credential for the key as a new version of its secret,
// creating the secret when it doesn't exist. Returns an error if the key
// isn't valid, or the value isn't JSON.
func (self *Manager) Set(ctx context.Context, key string, value json.RawMessage) (err error) {
	ctx, endSpan := otel.StartSpan(self.tracer, ctx, "credential.aws.Set",
		attribute.String("key", key),
	)
	defer func() { endSpan(err) }()

	if err := validateKey(key); err != nil {
		return err
	} else if !json.Valid(value) {
		return auth.ErrBadParameter.Withf("credential %q is not JSON", key)
	}

	// Add a version to the secret, or create it when it doesn't exist. When
	// another writer creates it first, add a version to theirs.
	name := self.name(key)
	err = self.put(ctx, name, string(value))
	if errors.Is(err, auth.ErrNotFound) {
		err = self.create(ctx, name, string(value))
		if errors.Is(err, auth.ErrConflict) {
			err = self.put(ctx, name, string(value))
		}
	}
	return err
}

// List returns the stored credentials, in key order, without their values:
// the secrets whose names start with the prefix, and the rest of which is a
// key. Secrets which are scheduled for deletion aren't listed.
func (self *Manager) List(ctx context.Context) (_ []credential.Credential, err error) {
	ctx, endSpan := otel.StartSpan(self.tracer, ctx, "credential.aws.List",
		attribute.String("prefix", self.prefix),
	)
	defer func() { endSpan(err) }()

	input := &secretsmanager.ListSecretsInput{
		SortOrder: smtypes.SortOrderTypeAsc,
	}
	if self.prefix != "" {
		input.Filters = []smtypes.Filter{{Key: smtypes.FilterNameStringTypeName, Values: []string{self.prefix}}}
	}
	var result []credential.Credential
	for {
		output, err := self.client.ListSecrets(ctx, input)
		if err != nil {
			return nil, awsErr(self.prefix, err)
		}
		for _, entry := range output.SecretList {
			// The name filter isn't case-sensitive, so check the prefix again
			key, ok := strings.CutPrefix(awssdk.ToString(entry.Name), self.prefix)
			if !ok || validateKey(key) != nil {
				continue
			}
			updated := awssdk.ToTime(entry.LastChangedDate)
			if updated.IsZero() {
				updated = awssdk.ToTime(entry.CreatedDate)
			}
			result = append(result, credential.Credential{Key: key, Description: awssdk.ToString(entry.Description), UpdatedAt: updated.UTC()})
		}
		if awssdk.ToString(output.NextToken) == "" {
			break
		}
		input.NextToken = output.NextToken
	}
	slices.SortFunc(result, func(a, b credential.Credential) int {
		return strings.Compare(a.Key, b.Key)
	})
	return result, nil
}

// Describe sets the description of the key's secret, which AWS keeps
// beside it, unencrypted, or removes it, when it's empty, without changing
// its value, and returns ErrNotFound when there isn't one
func (self *Manager) Describe(ctx context.Context, key, description string) (err error) {
	ctx, endSpan := otel.StartSpan(self.tracer, ctx, "credential.aws.Describe",
		attribute.String("key", key),
	)
	defer func() { endSpan(err) }()

	if err := validateKey(key); err != nil {
		return err
	}
	if _, err := self.client.UpdateSecret(ctx, &secretsmanager.UpdateSecretInput{
		SecretId:    awssdk.String(self.name(key)),
		Description: awssdk.String(strings.TrimSpace(description)),
	}); err != nil {
		return awsErr(key, err)
	}
	return nil
}

// Delete schedules the key's secret for deletion, after the recovery window
// set with WithRecoveryWindow, or AWS's default of 30 days, or deletes it
// at once when the window is zero. A secret with the key can't be created
// again until the deletion is complete. Returns ErrNotFound when there
// isn't one.
func (self *Manager) Delete(ctx context.Context, key string) (err error) {
	ctx, endSpan := otel.StartSpan(self.tracer, ctx, "credential.aws.Delete",
		attribute.String("key", key),
	)
	defer func() { endSpan(err) }()

	if err := validateKey(key); err != nil {
		return err
	}
	input := &secretsmanager.DeleteSecretInput{SecretId: awssdk.String(self.name(key))}
	switch {
	case self.recoveryDays == nil:
	case *self.recoveryDays == 0:
		input.ForceDeleteWithoutRecovery = awssdk.Bool(true)
	default:
		input.RecoveryWindowInDays = awssdk.Int64(int64(*self.recoveryDays))
	}
	if _, err := self.client.DeleteSecret(ctx, input); err != nil {
		return awsErr(key, err)
	}
	return nil
}

////////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// name returns the secret name for the key
func (self *Manager) name(key string) string {
	return self.prefix + key
}

// lookup returns the credential for the placeholder name, which must be a
// string. An environment variable is used as it is, as it's a string even
// when it looks like JSON, such as a number.
func (self *Manager) lookup(ctx context.Context, name string) (string, error) {
	if err := validateKey(name); err != nil {
		return "", auth.ErrBadParameter.Withf("invalid credential placeholder %q", name)
	}
	value, err := self.read(ctx, name)
	if errors.Is(err, auth.ErrNotFound) && self.env != nil {
		return self.env.Expand(ctx, "${"+name+"}")
	} else if err != nil {
		return "", err
	}

	// A secret which is a JSON string is used without its quotes, and one
	// which isn't JSON is used as it is
	if !json.Valid([]byte(value)) {
		return value, nil
	}
	var result string
	if err := json.Unmarshal([]byte(value), &result); err != nil {
		return "", auth.ErrBadParameter.Withf("credential %q is not a string", name)
	}
	return result, nil
}

// read returns the current version of the key's secret, which must be a
// string, or ErrNotFound when there is no secret for it
func (self *Manager) read(ctx context.Context, key string) (string, error) {
	output, err := self.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: awssdk.String(self.name(key)),
	})
	if err != nil {
		return "", awsErr(key, err)
	} else if output.SecretString == nil {
		return "", auth.ErrBadParameter.Withf("credential %q is a binary secret, which isn't supported", key)
	}
	return *output.SecretString, nil
}

// put adds a version to the secret, which becomes its current version
func (self *Manager) put(ctx context.Context, name, value string) error {
	if _, err := self.client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
		SecretId:     awssdk.String(name),
		SecretString: awssdk.String(value),
	}); err != nil {
		return awsErr(name, err)
	}
	return nil
}

// create creates the secret, with the KMS key when it's set
func (self *Manager) create(ctx context.Context, name, value string) error {
	input := &secretsmanager.CreateSecretInput{
		Name:         awssdk.String(name),
		SecretString: awssdk.String(value),
	}
	if self.kmsKeyID != "" {
		input.KmsKeyId = awssdk.String(self.kmsKeyID)
	}
	if _, err := self.client.CreateSecret(ctx, input); err != nil {
		return awsErr(name, err)
	}
	return nil
}

// awsErr converts a Secrets Manager error to an auth error, which wraps it
func awsErr(key string, err error) error {
	var notFound *smtypes.ResourceNotFoundException
	var exists *smtypes.ResourceExistsException
	var invalidParameter *smtypes.InvalidParameterException
	var invalidRequest *smtypes.InvalidRequestException
	var decryption *smtypes.DecryptionFailure
	var api smithy.APIError
	switch {
	case errors.As(err, &notFound):
		return auth.ErrNotFound.Withf("credential %q not found: %w", key, err)
	case errors.As(err, &exists):
		return auth.ErrConflict.Withf("credential %q: %w", key, err)
	case errors.As(err, &invalidParameter), errors.As(err, &invalidRequest):
		return auth.ErrBadParameter.Withf("credential %q: %w", key, err)
	case errors.As(err, &decryption):
		return auth.ErrForbidden.Withf("credential %q: %w", key, err)
	case errors.As(err, &api):
		switch api.ErrorCode() {
		case "AccessDeniedException", "UnrecognizedClientException", "InvalidSignatureException", "ExpiredTokenException":
			return auth.ErrForbidden.Withf("credential %q: %w", key, err)
		}
	}
	return auth.ErrServiceUnavailable.Withf("credential %q: %w", key, err)
}

// validateKey returns an error if the key isn't an identifier
func validateKey(key string) error {
	if !types.IsIdentifier(key) {
		return auth.ErrBadParameter.Withf("credential key %q must be an identifier", key)
	}
	return nil
}
