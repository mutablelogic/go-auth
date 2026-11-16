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

package manager

import (
	"encoding/json"
	"strings"

	// Packages
	ldap "github.com/go-ldap/ldap/v3"
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	changes "github.com/mutablelogic/go-server/broadcaster/schema"
)

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// setConn sets the manager's connection, and publishes a change of the
// connection when it comes up, or goes down
func (manager *Manager) setConn(conn *ldap.Conn) {
	was := manager.conn != nil
	manager.conn = conn
	switch {
	case !was && conn != nil:
		manager.publish(changes.ChangeCreate, schema.TableConnection, manager.url.Host, "")
	case was && conn == nil:
		manager.publish(changes.ChangeDelete, schema.TableConnection, manager.url.Host, "")
	}
}

// publish publishes a change of the table's row, with the row it was,
// when it's renamed, when the manager has a publisher
func (manager *Manager) publish(action changes.ChangeAction, table, row, previous string) {
	if manager.publisher == nil {
		return
	}
	change := changes.Change{Action: action, Schema: schema.SchemaName, Table: table, Row: row}
	if previous != "" && !sameRow(table, previous, row) {
		change.Data, _ = json.Marshal(map[string]string{"previous": previous})
	}
	manager.publisher.Publish(change)
}

// rdnValue returns the value of the DN's RDN, such as a user's name, or
// empty
func rdnValue(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil || len(parsed.RDNs) == 0 || len(parsed.RDNs[0].Attributes) == 0 {
		return ""
	}
	return parsed.RDNs[0].Attributes[0].Value
}

// sameRow returns whether two rows of the table are the same: an object's
// DNs which are equal, as directories return them in any case and spacing,
// and other rows, which are names, in any case
func sameRow(table, a, b string) bool {
	if strings.EqualFold(a, b) {
		return true
	} else if table != schema.TableObject {
		return false
	}
	x, errA := ldap.ParseDN(a)
	y, errB := ldap.ParseDN(b)
	return errA == nil && errB == nil && len(x.RDNs) > 0 && x.EqualFold(y)
}
