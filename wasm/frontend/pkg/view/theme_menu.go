package view

import (
	// Packages
	dom "github.com/djthorpe/go-wasmbuild"
	carbon "github.com/djthorpe/go-wasmbuild/pkg/carbon"
	mvc "github.com/djthorpe/go-wasmbuild/pkg/mvc"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// ThemeMenuView renders the theme selector overflow menu.
type ThemeMenuView struct {
	mvc.View
	items map[carbon.Attr]mvc.View
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func NewThemeMenuView(current, itemSize, iconSize carbon.Attr) *ThemeMenuView {
	menu := carbon.OverflowMenu(
		mvc.WithID("theme-selector"),
		carbon.Icon(carbon.IconSettings, carbon.With(iconSize)),
	).SetLabel("Theme selector")

	view := &ThemeMenuView{
		View:  menu,
		items: make(map[carbon.Attr]mvc.View, 4),
	}

	themes := []carbon.Attr{carbon.ThemeWhite, carbon.ThemeG10, carbon.ThemeG90, carbon.ThemeG100}
	children := make([]any, 0, len(themes))
	for _, theme := range themes {
		item := carbon.OverflowMenuItem().SetValue(string(theme))
		item.Apply(carbon.With(itemSize)...)
		view.items[theme] = item
		children = append(children, item)
	}
	menu.Content(children...)
	view.SetTheme(current)

	return view
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (view *ThemeMenuView) SetTheme(theme carbon.Attr) {
	if view == nil {
		return
	}
	for candidate, item := range view.items {
		setOverflowMenuItemLabel(item, themeLabel(candidate), candidate == theme)
	}
}

func (view *ThemeMenuView) OnSelect(handler func(carbon.Attr)) {
	if view == nil || handler == nil {
		return
	}
	for theme, item := range view.items {
		theme := theme
		item.AddEventListener(carbon.EventOverflowMenuItemClick, func(dom.Event) {
			handler(theme)
		})
	}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func themeLabel(theme carbon.Attr) string {
	switch theme {
	case carbon.ThemeWhite:
		return "White"
	case carbon.ThemeG10:
		return "Gray 10"
	case carbon.ThemeG90:
		return "Gray 90"
	case carbon.ThemeG100:
		return "Gray 100"
	default:
		return string(theme)
	}
}

func setOverflowMenuItemLabel(item mvc.View, label string, selected bool) {
	if item == nil {
		return
	}
	root := item.Root()
	root.SetInnerHTML(label)
	if selected {
		root.AppendChild(carbon.Icon(
			carbon.IconCheckmark,
			mvc.WithAttr("slot", "icon"),
			mvc.WithAttr("aria-hidden", "true"),
		).Root())
	}
}
