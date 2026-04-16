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

package ldapparser

import (
	"errors"
	"fmt"
	"strings"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	schema "github.com/mutablelogic/go-auth/schema/ldapparser"
	tokenizer "github.com/mutablelogic/go-tokenizer"
)

const scannerFeatures = tokenizer.HashComment | tokenizer.HyphenIdentToken

var errEmptyDefinition = errors.New("ldapparser: empty definition")

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

	result := &schema.ObjectClassSchema{
		Extensions: make(map[string][]string),
	}
	if err := p.expect(tokenizer.OpenParen); err != nil {
		return nil, err
	}

	oid, err := p.readOID(false)
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
				result.SuperClasses, err = p.readOIDList(false)
			case "ABSTRACT", "STRUCTURAL", "AUXILIARY":
				result.ClassKind = schema.ObjectClassKind(keyword)
			case "MUST":
				result.Must, err = p.readOIDList(false)
			case "MAY":
				result.May, err = p.readOIDList(false)
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

	result := &schema.AttributeTypeSchema{
		Extensions: make(map[string][]string),
	}
	if err := p.expect(tokenizer.OpenParen); err != nil {
		return nil, err
	}

	oid, err := p.readOID(false)
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
				result.SuperType, err = p.readOID(false)
			case "SYNTAX":
				result.Syntax, err = p.readOID(true)
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
	p.scanner = tokenizer.NewScanner(strings.NewReader(p.definition), tokenizer.Pos{}, scannerFeatures)
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
	if tok.Kind != tokenizer.EOF {
		return p.unexpected(tok, "end of definition")
	}
	return nil
}

func (p *parser) unexpected(tok *tokenizer.Token, expected string) error {
	if tok == nil {
		return auth.ErrBadParameter.Withf("ldapparser: expected %s", expected)
	}
	return tokenizer.NewPosError(
		auth.ErrBadParameter.Withf("ldapparser: expected %s, got %s %q", expected, tok.Kind, tok.Val),
		tok.Pos,
	)
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

func (p *parser) readOID(allowQuoted bool) (string, error) {
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

func (p *parser) readOIDList(allowQuoted bool) ([]string, error) {
	if p.peek().Kind != tokenizer.OpenParen {
		value, err := p.readOID(allowQuoted)
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
		case tokenizer.Dollar:
			p.next()
		default:
			value, err := p.readOID(allowQuoted)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
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
	return p.readOID(true)
}

func (p *parser) skipClauseValue(keyword string) error {
	_ = keyword
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
		_, err := p.readOID(true)
		if tok.Kind == tokenizer.String {
			return nil
		}
		return err
	default:
		return p.unexpected(tok, fmt.Sprintf("value for %q", keyword))
	}
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
