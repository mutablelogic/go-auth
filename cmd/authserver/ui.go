package main

import (
	frontend "github.com/djthorpe/go-auth/build/frontend.wasm"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
)

func registerUIHandlers(router *httprouter.Router) error {
	return router.RegisterFS("/", frontend.FrontendFS, false, nil)
}
