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

package test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	// Packages
	ber "github.com/go-asn1-ber/asn1-ber"
	ldapv3 "github.com/go-ldap/ldap/v3"
	require "github.com/stretchr/testify/require"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Fake is an LDAP directory in memory, which answers binds, searches of
// one entry, by its DN, adds, modifies and deletes, so tests can make a
// request stall, or another manager change something first, every time.
// It has no schema, filters, paging, renames or extended operations, so
// the directories in containers are for everything else.
type Fake struct {
	sync.Mutex
	listener    net.Listener
	entries     map[string]map[string][]string // by lower case DN
	connections int

	// When they're set, BeforeAdd and BeforeModify are called before an add
	// or modify of the DN is answered, and Stall stops a request of the
	// operation, such as ldap.ApplicationBindRequest, being answered
	BeforeAdd    func(dn string)
	BeforeModify func(dn string)
	Stall        func(op uint8, dn string) bool

	// The requests, as "op dn"
	requests []string
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// NewFake returns a directory listening on localhost, with TLS, whose
// certificate isn't trusted, when secure is true, which is closed when the
// test ends
func NewFake(t *testing.T, secure bool) *Fake {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	if secure {
		listener = tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}})
	}
	d := &Fake{listener: listener, entries: map[string]map[string][]string{}}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			d.Lock()
			d.connections++
			d.Unlock()
			go d.serve(conn)
		}
	}()
	return d
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// URL returns the directory's URL, with the user and password
func (d *Fake) URL(scheme string) string {
	return scheme + "://admin:secret@" + d.listener.Addr().String()
}

// Set sets an entry's attributes
func (d *Fake) Set(dn string, attrs map[string][]string) {
	d.Lock()
	defer d.Unlock()
	d.entries[strings.ToLower(dn)] = attrs
}

// Entry returns an entry's attributes, or nil
func (d *Fake) Entry(dn string) map[string][]string {
	d.Lock()
	defer d.Unlock()
	return d.entries[strings.ToLower(dn)]
}

// Connections returns how many connections the directory has accepted
func (d *Fake) Connections() int {
	d.Lock()
	defer d.Unlock()
	return d.connections
}

// Requests returns the requests of the operation, as their DNs: "bind",
// "search", "add", "modify" or "delete"
func (d *Fake) Requests(op string) []string {
	d.Lock()
	defer d.Unlock()
	var result []string
	for _, request := range d.requests {
		if name, dn, _ := strings.Cut(request, " "); name == op {
			result = append(result, dn)
		}
	}
	return result
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func (d *Fake) serve(conn net.Conn) {
	defer conn.Close()
	for {
		packet, err := ber.ReadPacket(conn)
		if err != nil || len(packet.Children) < 2 {
			return
		}
		id := packet.Children[0].Value
		request := packet.Children[1]
		var responses []*ber.Packet
		switch op := uint8(request.Tag); op {
		case ldapv3.ApplicationBindRequest:
			if d.record(op, "bind", request.Children[1].Data.String()) {
				continue
			}
			responses = []*ber.Packet{result(id, ldapv3.ApplicationBindResponse, 0)}
		case ldapv3.ApplicationSearchRequest:
			responses = d.search(id, request.Children[0].Data.String())
		case ldapv3.ApplicationAddRequest:
			responses = d.add(id, request)
		case ldapv3.ApplicationModifyRequest:
			responses = d.modify(id, request)
		case ldapv3.ApplicationDelRequest:
			responses = d.del(id, request.Data.String())
		case ldapv3.ApplicationUnbindRequest:
			return
		default:
			continue
		}
		for _, response := range responses {
			if _, err := conn.Write(response.Bytes()); err != nil {
				return
			}
		}
	}
}

// record records the request, and returns true when it should stall
func (d *Fake) record(op uint8, name, dn string) bool {
	d.Lock()
	d.requests = append(d.requests, name+" "+dn)
	stall := d.Stall
	d.Unlock()
	return stall != nil && stall(op, dn)
}

func (d *Fake) search(id any, dn string) []*ber.Packet {
	if d.record(ldapv3.ApplicationSearchRequest, "search", dn) {
		return nil
	}
	attrs := d.Entry(dn)
	if attrs == nil {
		return []*ber.Packet{result(id, ldapv3.ApplicationSearchResultDone, ldapv3.LDAPResultNoSuchObject)}
	}
	entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldapv3.ApplicationSearchResultEntry, nil, "Entry")
	entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "DN"))
	list := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	for name, values := range attrs {
		attr := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attribute")
		attr.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "Type"))
		set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "Values")
		for _, value := range values {
			set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, "Value"))
		}
		attr.AppendChild(set)
		list.AppendChild(attr)
	}
	entry.AppendChild(list)
	return []*ber.Packet{envelope(id, entry), result(id, ldapv3.ApplicationSearchResultDone, 0)}
}

func (d *Fake) add(id any, request *ber.Packet) []*ber.Packet {
	dn := request.Children[0].Data.String()
	if d.record(ldapv3.ApplicationAddRequest, "add", dn) {
		return nil
	}
	if d.BeforeAdd != nil {
		d.BeforeAdd(dn)
	}
	if d.Entry(dn) != nil {
		return []*ber.Packet{result(id, ldapv3.ApplicationAddResponse, ldapv3.LDAPResultEntryAlreadyExists)}
	}
	attrs := map[string][]string{}
	for _, attr := range request.Children[1].Children {
		for _, value := range attr.Children[1].Children {
			attrs[attr.Children[0].Data.String()] = append(attrs[attr.Children[0].Data.String()], value.Data.String())
		}
	}
	d.Set(dn, attrs)
	return []*ber.Packet{result(id, ldapv3.ApplicationAddResponse, 0)}
}

func (d *Fake) modify(id any, request *ber.Packet) []*ber.Packet {
	dn := request.Children[0].Data.String()
	if d.record(ldapv3.ApplicationModifyRequest, "modify", dn) {
		return nil
	}
	if d.BeforeModify != nil {
		d.BeforeModify(dn)
	}
	d.Lock()
	defer d.Unlock()
	attrs := d.entries[strings.ToLower(dn)]
	if attrs == nil {
		return []*ber.Packet{result(id, ldapv3.ApplicationModifyResponse, ldapv3.LDAPResultNoSuchObject)}
	}
	for _, change := range request.Children[1].Children {
		op := change.Children[0].Value.(int64)
		name := change.Children[1].Children[0].Data.String()
		var values []string
		for _, value := range change.Children[1].Children[1].Children {
			values = append(values, value.Data.String())
		}
		switch op {
		case ldapv3.AddAttribute:
			attrs[name] = append(attrs[name], values...)
		case ldapv3.ReplaceAttribute:
			attrs[name] = values
		case ldapv3.DeleteAttribute:
			// Deleting a value which isn't there fails, as it does in LDAP
			for _, value := range values {
				if !contains(attrs[name], value) {
					return []*ber.Packet{result(id, ldapv3.ApplicationModifyResponse, ldapv3.LDAPResultNoSuchAttribute)}
				}
			}
			if len(values) == 0 {
				delete(attrs, name)
			} else {
				var kept []string
				for _, value := range attrs[name] {
					if !contains(values, value) {
						kept = append(kept, value)
					}
				}
				attrs[name] = kept
			}
		}
	}
	return []*ber.Packet{result(id, ldapv3.ApplicationModifyResponse, 0)}
}

func (d *Fake) del(id any, dn string) []*ber.Packet {
	if d.record(ldapv3.ApplicationDelRequest, "delete", dn) {
		return nil
	}
	d.Lock()
	defer d.Unlock()
	if _, ok := d.entries[strings.ToLower(dn)]; !ok {
		return []*ber.Packet{result(id, ldapv3.ApplicationDelResponse, ldapv3.LDAPResultNoSuchObject)}
	}
	delete(d.entries, strings.ToLower(dn))
	return []*ber.Packet{result(id, ldapv3.ApplicationDelResponse, 0)}
}

// result returns a response to the message, with the result code
func result(id any, tag uint8, code uint16) *ber.Packet {
	response := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(tag), nil, "Response")
	response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(code), "resultCode"))
	response.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	response.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
	return envelope(id, response)
}

// envelope returns the LDAP message of the response to the message
func envelope(id any, response *ber.Packet) *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "MessageID"))
	packet.AppendChild(response)
	return packet
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

// selfSigned returns a certificate for 127.0.0.1, which signs itself
func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
