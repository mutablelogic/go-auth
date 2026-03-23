package view

import (
	// Packages
	carbon "github.com/djthorpe/go-wasmbuild/pkg/carbon"
	mvc "github.com/djthorpe/go-wasmbuild/pkg/mvc"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// HeaderNavView renders the app header and exposes its primary nav item.
type HeaderNavView struct {
	mvc.View
	auth mvc.View
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func NewHeaderNavView(themeSelector, userInfo mvc.View) *HeaderNavView {
	headerGlobal := carbon.HeaderNavGlobal(themeSelector, userInfo)
	headerNavItem := carbon.HeaderNavItem("#auth", "Auth")
	header := carbon.Header(
		headerNavItem,
		headerGlobal,
	).SetLabel("/wasm_exec.html", "Go Auth", "Console").SetActive(headerNavItem)

	return &HeaderNavView{
		View: header,
		auth: headerNavItem,
	}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (view *HeaderNavView) Auth() mvc.View {
	if view == nil {
		return nil
	}
	return view.auth
}
