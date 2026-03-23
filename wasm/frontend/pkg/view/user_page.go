package view

import (
	"strings"
	"time"

	// Packages
	schema "github.com/djthorpe/go-auth/schema"
	dom "github.com/djthorpe/go-wasmbuild"
	carbon "github.com/djthorpe/go-wasmbuild/pkg/carbon"
	mvc "github.com/djthorpe/go-wasmbuild/pkg/mvc"
)

const (
	ViewUserPage     = "go-auth-user-page"
	templateUserPage = `<div><div data-slot="toolbar"></div><div data-slot="table"></div><div data-slot="pagination"></div></div>`
	defaultUserLimit = 50
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// UserView renders a list of users in a Carbon data table.
type UserView struct {
	mvc.View
	createUser mvc.View
	toolbar    mvc.View
	table      mvc.View
	pagination paginationView
}

type paginationView interface {
	mvc.View
	mvc.EnabledState
	mvc.PaginationState
}

var _ mvc.View = (*UserView)(nil)
var _ mvc.PaginationState = (*UserView)(nil)
var _ mvc.VisibleState = (*UserView)(nil)

func init() {
	mvc.RegisterView(ViewUserPage, func(element dom.Element) mvc.View {
		return mvc.NewViewWithElement(new(UserView), element, setUserView)
	})
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func NewUserView() *UserView {
	return mvc.NewView(new(UserView), ViewUserPage, templateUserPage, setUserView).(*UserView)
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (view *UserView) SetLoading() {
	if view == nil {
		return
	}
	view.SetVisible(false)
	if view.pagination != nil {
		view.pagination.SetEnabled(false)
	}
}

func (view *UserView) Visible() bool {
	if view == nil {
		return false
	}
	return !view.Root().HasAttribute("hidden")
}

func (view *UserView) SetVisible(visible bool) mvc.View {
	if view == nil {
		return nil
	}
	if visible {
		view.Root().RemoveAttribute("hidden")
	} else {
		view.Root().SetAttribute("hidden", "")
	}
	return view
}

func (view *UserView) Content(args ...any) mvc.View {
	if view == nil {
		return nil
	}
	if len(args) == 1 {
		switch value := args[0].(type) {
		case schema.UserList:
			view.setUsers(value)
			return view
		case []schema.User:
			view.setUsers(schema.UserList{Count: uint(len(value)), Body: value})
			return view
		}
	}
	return view.View.Content(args...)
}

func (view *UserView) CreateUserButton() mvc.View {
	if view == nil {
		return nil
	}
	return view.createUser
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func setUserView(self mvc.View, child mvc.View) {
	view := self.(*UserView)
	view.View = child
	view.createUser = carbon.Button(
		carbon.With(carbon.KindPrimary, carbon.SizeSmall),
		"Create User",
		carbon.Icon(carbon.IconAdd, carbon.With(carbon.IconSize16)),
	)
	view.toolbar = carbon.TableToolbar(
		carbon.With(carbon.SizeExtraSmall),
		mvc.WithStyle("inline-size:100%"),
		view.createUser,
	)
	view.table = carbon.Table(tableOpts())
	view.pagination = carbon.Pagination(
		carbon.With(carbon.SizeSmall),
		mvc.WithAttr("page-size-input-disabled", ""),
		mvc.WithStyle("inline-size:100%"),
	)
	view.pagination.Apply(mvc.WithAttr("items-per-page-text", ""))
	view.pagination.SetLimit(defaultUserLimit)
	view.pagination.SetCount(0)
	view.pagination.SetOffset(0)
	view.pagination.SetEnabled(false)
	view.SetVisible(false)
	view.ReplaceSlot("toolbar", view.toolbar)
	view.ReplaceSlot("table", view.table)
	view.ReplaceSlot("pagination", view.pagination)
	view.Apply(rootOpts()...)
	view.renderHeader()
	view.renderRows(nil)
}

func (view *UserView) renderHeader() {
	if view == nil || view.table == nil {
		return
	}
	view.table.Apply(tableOpts()...)
	view.table.ReplaceSlotChildren("header",
		carbon.TableHeader("Name", "Email", "Status", "Groups", "Created"),
	)
}

func (view *UserView) renderRows(users []schema.User) {
	if view == nil || view.table == nil {
		return
	}

	rows := make([]any, 0, len(users))
	for _, user := range users {
		rows = append(rows, carbon.TableRow(
			displayName(user),
			user.Email,
			displayStatus(user.Status),
			displayGroups(user.Groups),
			displayTime(user.CreatedAt),
		))
	}

	view.table.ReplaceSlotChildren("body", rows...)
	view.table.Apply(tableOpts()...)
}

func (view *UserView) setUsers(list schema.UserList) {
	if view == nil {
		return
	}
	if view.pagination != nil {
		view.pagination.SetCount(list.Count)
		view.pagination.SetEnabled(true)
	}
	view.renderRows(list.Body)
	view.SetVisible(true)
}

func (view *UserView) Offset() uint {
	if view == nil || view.pagination == nil {
		return 0
	}
	return view.pagination.Offset()
}

func (view *UserView) SetOffset(offset uint) mvc.View {
	if view == nil || view.pagination == nil {
		return view
	}
	view.pagination.SetOffset(offset)
	return view
}

func (view *UserView) Limit() uint {
	if view == nil || view.pagination == nil {
		return 0
	}
	return view.pagination.Limit()
}

func (view *UserView) SetLimit(limit uint) mvc.View {
	if view == nil || view.pagination == nil {
		return view
	}
	view.pagination.SetLimit(limit)
	return view
}

func (view *UserView) Count() uint {
	if view == nil || view.pagination == nil {
		return 0
	}
	return view.pagination.Count()
}

func (view *UserView) SetCount(count uint) mvc.View {
	if view == nil || view.pagination == nil {
		return view
	}
	view.pagination.SetCount(count)
	return view
}

func rootOpts() []mvc.Opt {
	return []mvc.Opt{
		mvc.WithStyle("display:grid"),
	}
}

func tableOpts() []mvc.Opt {
	opts := carbon.With(carbon.SizeExtraSmall)
	return append(opts, mvc.WithStyle("inline-size:100%"))
}

func displayName(user schema.User) string {
	if name := strings.TrimSpace(user.Name); name != "" {
		return name
	}
	if email := strings.TrimSpace(user.Email); email != "" {
		return email
	}
	return user.ID.String()
}

func displayStatus(status *schema.UserStatus) string {
	if status == nil || *status == "" {
		return "active"
	}
	return string(*status)
}

func displayGroups(groups []string) string {
	if len(groups) == 0 {
		return "-"
	}
	return strings.Join(groups, ", ")
}

func displayTime(ts time.Time) string {
	if ts.IsZero() {
		return "-"
	}
	return ts.Format("2006-01-02")
}
