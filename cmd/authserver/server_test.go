//go:build !client

package main

import (
	"testing"

	assert "github.com/stretchr/testify/assert"
)

func Test_publicHostPort_001(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		assert.Equal(t, "", publicHostPort(""))
	})

	t.Run("PortOnlyUsesLocalhost", func(t *testing.T) {
		assert.Equal(t, "localhost:8084", publicHostPort(":8084"))
	})

	t.Run("WildcardIPv4UsesLocalhost", func(t *testing.T) {
		assert.Equal(t, "localhost:8084", publicHostPort("0.0.0.0:8084"))
	})

	t.Run("WildcardIPv6UsesLocalhost", func(t *testing.T) {
		assert.Equal(t, "localhost:8084", publicHostPort("[::]:8084"))
	})

	t.Run("ExplicitHostPreserved", func(t *testing.T) {
		assert.Equal(t, "127.0.0.1:8084", publicHostPort("127.0.0.1:8084"))
		assert.Equal(t, "example.test:8084", publicHostPort("example.test:8084"))
	})

	t.Run("OpaqueAddressPreserved", func(t *testing.T) {
		assert.Equal(t, "localhost", publicHostPort("localhost"))
	})
}
