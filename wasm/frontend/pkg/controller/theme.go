package controller

import (
	// Packages
	view "github.com/djthorpe/go-auth/wasm/frontend/pkg/view"
	carbon "github.com/djthorpe/go-wasmbuild/pkg/carbon"
	js "github.com/djthorpe/go-wasmbuild/pkg/js"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// ThemeController coordinates theme selection and applies the selected Carbon theme.
type ThemeController struct {
	theme carbon.Attr
	view  *view.ThemeMenuView
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// NewThemeController creates a controller with the given initial theme.
func NewThemeController(theme carbon.Attr) *ThemeController {
	return &ThemeController{theme: theme}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Bind wires the theme selector menu to document theme application.
func (controller *ThemeController) Bind(view *view.ThemeMenuView) *ThemeController {
	if controller == nil || view == nil {
		return controller
	}
	controller.view = view
	view.OnSelect(func(theme carbon.Attr) {
		controller.SetTheme(theme)
	})
	controller.SetTheme(controller.theme)
	return controller
}

// SetTheme updates the selected theme in the menu and applies it to the document body.
func (controller *ThemeController) SetTheme(theme carbon.Attr) {
	if controller == nil {
		return
	}
	controller.theme = theme
	if controller.view != nil {
		controller.view.SetTheme(theme)
	}
	applyTheme(theme)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func applyTheme(theme carbon.Attr) {
	body := js.Global().Get("document").Get("body")
	if body.IsUndefined() || body.IsNull() {
		return
	}
	classList := body.Get("classList")
	for _, candidate := range []carbon.Attr{carbon.ThemeWhite, carbon.ThemeG10, carbon.ThemeG90, carbon.ThemeG100} {
		classList.Call("remove", carbon.ClassForTheme(candidate))
	}
	classList.Call("add", carbon.ClassForTheme(theme))
}
