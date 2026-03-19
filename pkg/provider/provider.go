package provider

import (
	"fmt"
	"net/url"

	// Packages
	schema "github.com/djthorpe/go-auth/schema"
	js "github.com/djthorpe/go-wasmbuild/pkg/js"
	mvc "github.com/djthorpe/go-wasmbuild/pkg/mvc"
)

type Provider struct {
	mvc.Provider
}

func New(base *url.URL) *Provider {
	self := &Provider{
		mvc.NewProvider(base),
	}
	self.AddEventListener(func(resp *js.FetchResponse, err error) {
		fmt.Println("User event:", resp, err)
	})
	return self

}

func (p *Provider) CreateUser(meta schema.UserMeta) {
	p.Fetch("user", js.WithMethod("POST"), js.WithBody(meta))
}
