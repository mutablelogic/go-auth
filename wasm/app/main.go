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

package main

import (
	// Packages
	dom "github.com/djthorpe/go-wasmbuild"
	mvc "github.com/djthorpe/go-wasmbuild/pkg/mvc"
)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func main() {
	mvc.New("hello, world").Run()
}

///////////////////////////////////////////////////////////////////////////////
// TYPES

type app struct {
	mvc.View
}

///////////////////////////////////////////////////////////////////////////////
// GLOBAL VARIABLES

const (
	AppView = "app-view"
)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func init() {
	mvc.RegisterView(AppView, func(element dom.Element) mvc.View {
		return mvc.NewViewWithElement(new(app), element, nil)
	})
}

func App() mvc.View {
	return mvc.NewView(new(app), AppView, "cds-button", func(self, child mvc.View) {
		self.(*app).View = child
	})
}
