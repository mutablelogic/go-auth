package schema

///////////////////////////////////////////////////////////////////////////////
// TYPES

// ChangeNotification is emitted for table changes when database notifications
// are enabled on the manager.
type ChangeNotification struct {
	Schema string `json:"schema"`
	Table  string `json:"table"`
	Action string `json:"action"`
}
