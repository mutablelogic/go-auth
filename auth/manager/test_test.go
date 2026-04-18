package manager_test

import (
	"testing"
	"time"

	// Packages
	manager "github.com/mutablelogic/go-auth/auth/manager"
	localprovider "github.com/mutablelogic/go-auth/auth/provider/local"
	authtest "github.com/mutablelogic/go-auth/auth/test"
	authcrypto "github.com/mutablelogic/go-auth/crypto"
)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

var (
	shared *manager.Manager
)

const (
	DefaultIssuer     = "https://issuer/"
	DefaultSessionTTL = 15 * time.Minute
)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func TestMain(m *testing.M) {
	key, err := authcrypto.GeneratePrivateKey()
	if err != nil {
		panic(err)
	}
	provider, err := localprovider.New(DefaultIssuer, key)
	if err != nil {
		panic(err)
	}

	authtest.Main(m, func(mgr *manager.Manager) (func(), error) {
		shared = mgr
		return func() {
			shared = nil
		}, nil
	},
		manager.WithSigner("test-main", key),
		manager.WithProvider(provider),
		manager.WithSessionTTL(DefaultSessionTTL),
	)
}
