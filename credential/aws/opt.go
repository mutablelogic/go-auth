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
	"strings"

	// Packages
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awscredentials "github.com/aws/aws-sdk-go-v2/credentials"
	auth "github.com/mutablelogic/go-auth"
	credential "github.com/mutablelogic/go-auth/credential"
	env "github.com/mutablelogic/go-auth/credential/env"
	trace "go.opentelemetry.io/otel/trace"
)

////////////////////////////////////////////////////////////////////////////////
// TYPES

// Opt is a functional option for the AWS credential manager
type Opt func(*opt) error

type opt struct {
	tracer   trace.Tracer
	prefix   string
	kmsKeyID string
	// recoveryDays is the recovery window of a deleted secret, or nil for
	// AWS's default
	recoveryDays *int
	config       []func(*awsconfig.LoadOptions) error
	client       client
	env          credential.CredentialProvider
	useEnv       bool
}

////////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func (o *opt) apply(opts []Opt) error {
	for _, fn := range opts {
		if err := fn(o); err != nil {
			return err
		}
	}

	// The environment provider uses the tracer, which can be set after
	// WithEnv
	if o.useEnv {
		o.env = env.New(env.WithTracer(o.tracer))
	}
	return nil
}

////////////////////////////////////////////////////////////////////////////////
// OPTIONS

// WithTracer sets the tracer used for tracing operations
func WithTracer(tracer trace.Tracer) Opt {
	return func(o *opt) error {
		o.tracer = tracer
		return nil
	}
}

// WithRegion sets the AWS region, in place of AWS_REGION or the profile's
func WithRegion(region string) Opt {
	return func(o *opt) error {
		if region == "" {
			return auth.ErrBadParameter.With("region is empty")
		}
		o.config = append(o.config, awsconfig.WithRegion(region))
		return nil
	}
}

// WithProfile sets the shared configuration profile, in place of AWS_PROFILE
func WithProfile(profile string) Opt {
	return func(o *opt) error {
		if profile == "" {
			return auth.ErrBadParameter.With("profile is empty")
		}
		o.config = append(o.config, awsconfig.WithSharedConfigProfile(profile))
		return nil
	}
}

// WithCredentials sets static credentials, in place of AWS_ACCESS_KEY_ID,
// AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN, or the profile's. The
// session token is optional.
func WithCredentials(accessKeyID, secretAccessKey, sessionToken string) Opt {
	return func(o *opt) error {
		if accessKeyID == "" || secretAccessKey == "" {
			return auth.ErrBadParameter.With("access key ID and secret access key are required")
		}
		o.config = append(o.config, awsconfig.WithCredentialsProvider(
			awscredentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, sessionToken),
		))
		return nil
	}
}

// WithEndpoint sets the endpoint URL, in place of AWS_ENDPOINT_URL, such as
// for a local emulator
func WithEndpoint(endpoint string) Opt {
	return func(o *opt) error {
		if endpoint == "" {
			return auth.ErrBadParameter.With("endpoint is empty")
		}
		o.config = append(o.config, awsconfig.WithBaseEndpoint(endpoint))
		return nil
	}
}

// WithPrefix sets a prefix for the secret names, such as "myapp/", so the
// credential for key KEY is the secret "myapp/KEY"
func WithPrefix(prefix string) Opt {
	return func(o *opt) error {
		if strings.Trim(prefix, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_+=.@-") != "" {
			return auth.ErrBadParameter.Withf("prefix %q has characters which aren't allowed in a secret name", prefix)
		}
		o.prefix = prefix
		return nil
	}
}

// WithKMSKey sets the KMS key which new secrets are encrypted with, in place
// of the account's default key for Secrets Manager
func WithKMSKey(keyID string) Opt {
	return func(o *opt) error {
		if keyID == "" {
			return auth.ErrBadParameter.With("KMS key is empty")
		}
		o.kmsKeyID = keyID
		return nil
	}
}

// WithRecoveryWindow sets the number of days, from 7 to 30, that a deleted
// secret can be recovered for, in place of AWS's default of 30 days, or 0 to
// delete secrets at once, without recovery
func WithRecoveryWindow(days int) Opt {
	return func(o *opt) error {
		if days != 0 && (days < 7 || days > 30) {
			return auth.ErrBadParameter.Withf("recovery window of %d days isn't 0, or from 7 to 30", days)
		}
		o.recoveryDays = &days
		return nil
	}
}

// WithEnv reads a credential from the environment when there is no secret
// for it, so $KEY is expanded from the environment variable KEY. The
// environment is read-only, so credentials are still stored as secrets.
func WithEnv() Opt {
	return func(o *opt) error {
		o.useEnv = true
		return nil
	}
}

// withClient sets the Secrets Manager client, in place of one from the AWS
// configuration, for tests
func withClient(c client) Opt {
	return func(o *opt) error {
		o.client = c
		return nil
	}
}
