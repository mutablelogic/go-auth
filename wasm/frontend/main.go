package main

import (
	auth "github.com/djthorpe/go-auth/wasm/frontend/pkg/auth"
	mvc "github.com/djthorpe/go-wasmbuild/pkg/mvc"
)

var frontendAuth *auth.Auth

func main() {
	mvc.New(newApp()).Run()
}

func newApp() any {
	frontendAuth = auth.New()

	return mvc.HTML("DIV", "hello,world!")
}
