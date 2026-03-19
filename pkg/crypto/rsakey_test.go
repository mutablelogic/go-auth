package crypto_test

import (
	"testing"

	authcrypto "github.com/djthorpe/go-auth/pkg/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrivateKeyPEMRoundTrip(t *testing.T) {
	key, err := authcrypto.GeneratePrivateKey()
	require.NoError(t, err)

	pemValue, err := authcrypto.PrivateKeyPEM(key)
	require.NoError(t, err)
	assert.NotEmpty(t, pemValue)

	parsed, err := authcrypto.ParsePrivateKeyPEM(pemValue)
	require.NoError(t, err)
	assert.Equal(t, key.N, parsed.N)
	assert.Equal(t, key.E, parsed.E)
	assert.Equal(t, key.D, parsed.D)
}

func TestPrivateKeyPEMRequiresKey(t *testing.T) {
	_, err := authcrypto.PrivateKeyPEM(nil)
	require.Error(t, err)
}

func TestParsePrivateKeyPEMRejectsInvalidData(t *testing.T) {
	_, err := authcrypto.ParsePrivateKeyPEM("not a pem")
	require.Error(t, err)
}