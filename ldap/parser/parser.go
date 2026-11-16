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

// Package ldapparser reads the RFC 4512 descriptions of LDAP object classes
// and attribute types, such as a directory's subschema publishes
package ldapparser

import (
	"fmt"
	"strings"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	schema "github.com/mutablelogic/go-auth/ldap/parser/schema"
	tokenizer "github.com/mutablelogic/go-tokenizer"
)

const scannerFeatures = tokenizer.HashComment | tokenizer.HyphenIdentToken

var errEmptyDefinition = auth.ErrBadParameter.With("ldapparser: empty definition")

//////////////////////////////////////////////////////////////////////////////////
// INTERFACES

type Parser interface {
	ParseObjectClass() (*schema.ObjectClassSchema, error)
	ParseAttributeType() (*schema.AttributeTypeSchema, error)
}

//////////////////////////////////////////////////////////////////////////////////
// TYPES

type parser struct {
	definition string
	scanner    *tokenizer.Scanner
}

//////////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func New(definition string) Parser {
	return &parser{definition: strings.TrimSpace(definition)}
}

//////////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (p *parser) ParseObjectClass() (*schema.ObjectClassSchema, error) {
	if err := p.reset(); err != nil {
		return nil, err
	}

	// Without a kind, a class is STRUCTURAL (RFC 4512 4.1.1)
	result := &schema.ObjectClassSchema{
		ClassKind:  schema.ObjectClassKindStructural,
		Extensions: make(map[string][]string),
	}
	if err := p.expect(tokenizer.OpenParen); err != nil {
		return nil, err
	}

	// The leading OID is numeric, or a descriptor, as 389 DS's schema has,
	// such as nsCertConfig-oid, but never quoted, or with a length
	oid, err := p.readOID(false, false)
	if err != nil {
		return nil, err
	}
	result.NumericOID = oid

	for {
		tok := p.peek()
		switch tok.Kind {
		case tokenizer.CloseParen:
			p.next()
			return result, p.expectEOF()
		case tokenizer.EOF:
			return nil, p.unexpected(tok, ")")
		case tokenizer.Ident:
			keyword := strings.ToUpper(p.next().Val)
			switch keyword {
			case "NAME":
				result.Name, err = p.readQDStrings()
			case "DESC":
				result.Description, err = p.readQuotedString()
			case "OBSOLETE":
				result.Obsolete = true
			case "SUP":
				result.SuperClasses, err = p.readOIDList()
			case "ABSTRACT", "STRUCTURAL", "AUXILIARY":
				result.ClassKind = schema.ObjectClassKind(keyword)
			case "MUST":
				result.Must, err = p.readOIDList()
			case "MAY":
				result.May, err = p.readOIDList()
			default:
				if strings.HasPrefix(keyword, "X-") {
					result.Extensions[keyword], err = p.readExtensionValues()
				} else {
					err = p.skipClauseValue(keyword)
				}
			}
			if err != nil {
				return nil, err
			}
		default:
			return nil, p.unexpected(tok, "schema clause")
		}
	}
}

func (p *parser) ParseAttributeType() (*schema.AttributeTypeSchema, error) {
	if err := p.reset(); err != nil {
		return nil, err
	}

	// Without a usage, an attribute type is for user applications (RFC 4512 4.1.2)
	result := &schema.AttributeTypeSchema{
		Usage:      schema.AttributeUsageUserApplications,
		Extensions: make(map[string][]string),
	}
	if err := p.expect(tokenizer.OpenParen); err != nil {
		return nil, err
	}

	// The leading OID is numeric, or a descriptor, as 389 DS's schema has,
	// such as nsCertConfig-oid, but never quoted, or with a length
	oid, err := p.readOID(false, false)
	if err != nil {
		return nil, err
	}
	result.NumericOID = oid

	for {
		tok := p.peek()
		switch tok.Kind {
		case tokenizer.CloseParen:
			p.next()
			return result, p.expectEOF()
		case tokenizer.EOF:
			return nil, p.unexpected(tok, ")")
		case tokenizer.Ident:
			keyword := strings.ToUpper(p.next().Val)
			switch keyword {
			case "NAME":
				result.Name, err = p.readQDStrings()
			case "DESC":
				result.Description, err = p.readQuotedString()
			case "OBSOLETE":
				result.Obsolete = true
			case "SUP":
				result.SuperType, err = p.readOID(false, false)
			case "SYNTAX":
				result.Syntax, err = p.readOID(true, true)
			case "SINGLE-VALUE":
				result.SingleValue = true
			case "COLLECTIVE":
				result.Collective = true
			case "NO-USER-MODIFICATION":
				result.NoUserModification = true
			case "USAGE":
				var usage string
				usage, err = p.readDescriptor()
				result.Usage = schema.AttributeUsage(usage)
			default:
				if strings.HasPrefix(keyword, "X-") {
					result.Extensions[keyword], err = p.readExtensionValues()
				} else {
					err = p.skipClauseValue(keyword)
				}
			}
			if err != nil {
				return nil, err
			}
		default:
			return nil, p.unexpected(tok, "schema clause")
		}
	}
}

//////////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func (p *parser) reset() error {
	if p == nil || strings.TrimSpace(p.definition) == "" {
		return errEmptyDefinition
	}
	definition, err := escapeQuoted(p.definition)
	if err != nil {
		return err
	}
	p.scanner = tokenizer.NewScanner(strings.NewReader(definition), tokenizer.Pos{}, scannerFeatures)
	return nil
}

func (p *parser) peek() *tokenizer.Token {
	p.skipIgnored()
	return p.scanner.Peak()
}

func (p *parser) next() *tokenizer.Token {
	p.skipIgnored()
	return p.scanner.Next()
}

func (p *parser) skipIgnored() {
	for p.scanner != nil {
		tok := p.scanner.Peak()
		if tok.Kind != tokenizer.Space && tok.Kind != tokenizer.Comment {
			return
		}
		p.scanner.Next()
	}
}

func (p *parser) expect(kind tokenizer.TokenKind, values ...string) error {
	tok := p.peek()
	if tok.Kind != kind {
		return p.unexpected(tok, expectedDescription(kind, values...))
	}
	if len(values) > 0 && !matchesTokenValue(tok, values...) {
		return p.unexpected(tok, expectedDescription(kind, values...))
	}
	p.next()
	return nil
}

func (p *parser) expectEOF() error {
	tok := p.peek()
	if err := p.scanErr(tok); err != nil {
		return err
	}
	if tok.Kind != tokenizer.EOF {
		return p.unexpected(tok, "end of definition")
	}
	return nil
}

func (p *parser) unexpected(tok *tokenizer.Token, expected string) error {
	if tok == nil {
		return auth.ErrBadParameter.Withf("ldapparser: expected %s", expected)
	}
	if err := p.scanErr(tok); err != nil {
		return err
	}
	// The position is in the message, as go-tokenizer's PosError doesn't
	// unwrap, so the error wouldn't be a bad parameter
	return auth.ErrBadParameter.Withf("ldapparser: %d:%d: expected %s, got %s %q", tok.Pos.Line+1, tok.Pos.Col+1, expected, tok.Kind, tok.Val)
}

func (p *parser) readQuotedString() (string, error) {
	tok := p.peek()
	if tok.Kind != tokenizer.String {
		return "", p.unexpected(tok, "quoted string")
	}
	return p.next().Val, nil
}

func (p *parser) readDescriptor() (string, error) {
	tok := p.peek()
	if tok.Kind != tokenizer.Ident {
		return "", p.unexpected(tok, "descriptor")
	}
	return p.next().Val, nil
}

func (p *parser) readQDStrings() ([]string, error) {
	if p.peek().Kind != tokenizer.OpenParen {
		value, err := p.readQuotedString()
		if err != nil {
			return nil, err
		}
		return []string{value}, nil
	}

	p.next()
	values := make([]string, 0, 4)
	for {
		tok := p.peek()
		switch tok.Kind {
		case tokenizer.CloseParen:
			p.next()
			return values, nil
		case tokenizer.String:
			values = append(values, p.next().Val)
		default:
			return nil, p.unexpected(tok, "quoted string or )")
		}
	}
}

// readOID reads a descriptor, or a numeric OID, with a length, such as a
// syntax has, when allowLength is true, or a quoted one, when allowQuoted
// is true
func (p *parser) readOID(allowQuoted, allowLength bool) (string, error) {
	tok := p.peek()
	switch tok.Kind {
	case tokenizer.Ident:
		return p.next().Val, nil
	case tokenizer.String:
		if !allowQuoted {
			return "", p.unexpected(tok, "descriptor or numeric OID")
		}
		return p.next().Val, nil
	case tokenizer.NumberInteger:
		var builder strings.Builder
		builder.WriteString(p.next().Val)
		for p.peek().Kind == tokenizer.Punkt {
			p.next()
			part := p.peek()
			if part.Kind != tokenizer.NumberInteger {
				return "", p.unexpected(part, "numeric OID segment")
			}
			builder.WriteRune('.')
			builder.WriteString(p.next().Val)
		}
		if p.peek().Kind == tokenizer.OpenBrace {
			if !allowLength {
				return "", p.unexpected(p.peek(), "numeric OID without a length")
			}
			p.next()
			part := p.peek()
			if part.Kind != tokenizer.NumberInteger {
				return "", p.unexpected(part, "length")
			}
			builder.WriteRune('{')
			builder.WriteString(p.next().Val)
			if err := p.expect(tokenizer.CloseBrace); err != nil {
				return "", err
			}
			builder.WriteRune('}')
		}
		return builder.String(), nil
	default:
		return "", p.unexpected(tok, "descriptor or numeric OID")
	}
}

// readOIDList reads an OID, or a list of them, which is at least one,
// separated by $
func (p *parser) readOIDList() ([]string, error) {
	if p.peek().Kind != tokenizer.OpenParen {
		value, err := p.readOID(false, false)
		if err != nil {
			return nil, err
		}
		return []string{value}, nil
	}

	p.next()
	values := make([]string, 0, 4)
	for {
		value, err := p.readOID(false, false)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
		switch tok := p.peek(); tok.Kind {
		case tokenizer.CloseParen:
			p.next()
			return values, nil
		case tokenizer.Dollar:
			p.next()
		default:
			return nil, p.unexpected(tok, "$ or )")
		}
	}
}

func (p *parser) readExtensionValues() ([]string, error) {
	if p.peek().Kind != tokenizer.OpenParen {
		value, err := p.readExtensionValue()
		if err != nil {
			return nil, err
		}
		return []string{value}, nil
	}

	p.next()
	values := make([]string, 0, 2)
	for {
		tok := p.peek()
		switch tok.Kind {
		case tokenizer.CloseParen:
			p.next()
			return values, nil
		default:
			value, err := p.readExtensionValue()
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
	}
}

func (p *parser) readExtensionValue() (string, error) {
	tok := p.peek()
	if tok.Kind == tokenizer.String {
		return p.next().Val, nil
	}
	return p.readOID(true, true)
}

func (p *parser) skipClauseValue(keyword string) error {
	tok := p.peek()
	switch tok.Kind {
	case tokenizer.OpenParen:
		depth := 0
		for {
			tok = p.next()
			switch tok.Kind {
			case tokenizer.OpenParen:
				depth++
			case tokenizer.CloseParen:
				depth--
				if depth == 0 {
					return nil
				}
			case tokenizer.EOF:
				return p.unexpected(tok, ")")
			}
		}
	case tokenizer.String, tokenizer.Ident, tokenizer.NumberInteger:
		_, err := p.readOID(true, true)
		if tok.Kind == tokenizer.String {
			return nil
		}
		return err
	default:
		return p.unexpected(tok, fmt.Sprintf("value for %q", keyword))
	}
}

// scanErr returns the scanner's error, as a bad parameter, when the token
// is the end of the definition because the scanner failed, such as at an
// unterminated string
func (p *parser) scanErr(tok *tokenizer.Token) error {
	if tok == nil || tok.Kind != tokenizer.EOF || p.scanner == nil {
		return nil
	}
	if err := p.scanner.Err(); err != nil {
		return auth.ErrBadParameter.Withf("ldapparser: %v", err)
	}
	return nil
}

// escapeQuoted rewrites RFC 4512's escapes in quoted strings, \27 for an
// apostrophe and \5C for a backslash, as the tokenizer's, \' and \\.
// Any other backslash in a quoted string is invalid. The rewritten escapes
// are a character shorter, so positions after them are a column earlier.
func escapeQuoted(definition string) (string, error) {
	var result strings.Builder
	result.Grow(len(definition))
	quoted := false
	for i := 0; i < len(definition); i++ {
		ch := definition[i]
		switch {
		case ch == '\'':
			quoted = !quoted
			result.WriteByte(ch)
		case ch == '\\' && quoted:
			escape := ""
			if i+2 < len(definition) {
				escape = strings.ToLower(definition[i+1 : i+3])
			}
			switch escape {
			case "27":
				result.WriteString(`\'`)
			case "5c":
				result.WriteString(`\\`)
			default:
				return "", auth.ErrBadParameter.Withf("ldapparser: invalid escape at %d, which is \\27 or \\5C", i+1)
			}
			i += 2
		default:
			result.WriteByte(ch)
		}
	}
	return result.String(), nil
}

func expectedDescription(kind tokenizer.TokenKind, values ...string) string {
	if len(values) == 0 {
		return kind.String()
	}
	return fmt.Sprintf("%s %q", kind, strings.Join(values, "|"))
}

func matchesTokenValue(tok *tokenizer.Token, values ...string) bool {
	for _, value := range values {
		if strings.EqualFold(tok.Val, value) {
			return true
		}
	}
	return false
}
