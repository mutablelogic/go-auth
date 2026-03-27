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
