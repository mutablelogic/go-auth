package crypto_test

import (
	"bytes"
	"testing"

	authcrypto "github.com/djthorpe/go-auth/pkg/crypto"
	assert "github.com/stretchr/testify/assert"
)

func TestCryptRoundTripBytes(t *testing.T) {
	assert := assert.New(t)
	plaintext := []byte("hello, world")
	blob, err := authcrypto.Encrypt("passphrase", plaintext)
	assert.NoError(err)
	assert.NotNil(blob)

	got, err := authcrypto.Decrypt[[]byte]("passphrase", blob)
	assert.NoError(err)
	assert.True(bytes.Equal(plaintext, got))
}

func TestCryptRoundTripString(t *testing.T) {
	assert := assert.New(t)
	blob, err := authcrypto.Encrypt("passphrase", "hello, world")
	assert.NoError(err)
	assert.NotNil(blob)

	got, err := authcrypto.Decrypt[string]("passphrase", blob)
	assert.NoError(err)
	assert.Equal("hello, world", got)
}

func TestCryptWrongPassphrase(t *testing.T) {
	assert := assert.New(t)
	blob, err := authcrypto.Encrypt("correct", []byte("secret"))
	assert.NoError(err)

	_, err = authcrypto.Decrypt[[]byte]("wrong", blob)
	assert.Error(err)
}

func TestCryptEmptyPlaintext(t *testing.T) {
	assert := assert.New(t)
	blob, err := authcrypto.Encrypt("pass", []byte(""))
	assert.NoError(err)

	got, err := authcrypto.Decrypt[[]byte]("pass", blob)
	assert.NoError(err)
	assert.Empty(got)
}

func TestCryptTruncatedBlob(t *testing.T) {
	assert := assert.New(t)
	_, err := authcrypto.Decrypt[[]byte]("pass", []byte("short"))
	assert.Error(err)
}

func TestCryptRandomizedOutput(t *testing.T) {
	assert := assert.New(t)
	blob1, err := authcrypto.Encrypt("pass", []byte("data"))
	assert.NoError(err)
	blob2, err := authcrypto.Encrypt("pass", []byte("data"))
	assert.NoError(err)
	assert.False(bytes.Equal(blob1, blob2))
}

func TestKeyEncryptDecryptRoundTrip(t *testing.T) {
	assert := assert.New(t)
	salt, err := authcrypto.GenerateSalt()
	assert.NoError(err)

	key := authcrypto.DeriveKey("passphrase", salt)
	ct, err := key.Encrypt([]byte("secret data"))
	assert.NoError(err)

	got, err := key.Decrypt(ct)
	assert.NoError(err)
	assert.Equal("secret data", string(got))
}

func TestKeyDecryptDifferentKeyFails(t *testing.T) {
	assert := assert.New(t)
	salt1, _ := authcrypto.GenerateSalt()
	salt2, _ := authcrypto.GenerateSalt()

	key1 := authcrypto.DeriveKey("pass", salt1)
	key2 := authcrypto.DeriveKey("pass", salt2)

	ct, err := key1.Encrypt([]byte("data"))
	assert.NoError(err)

	_, err = key2.Decrypt(ct)
	assert.Error(err)
}
