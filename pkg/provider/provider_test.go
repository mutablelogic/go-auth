package provider_test

import (
	"net/url"
	"testing"

	// Packages
	"github.com/djthorpe/go-auth/pkg/provider"
	"github.com/djthorpe/go-auth/schema"
)

func TestProvider(t *testing.T) {
	base, err := url.Parse("http://example.com/api/")
	if err != nil {
		t.Fatal(err)
	}
	p := provider.New(base)
	p.CreateUser(schema.UserMeta{
		Name: "Alice",
	})
}
