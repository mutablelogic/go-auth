package markdown

import (
	"strings"
)

// Section represents a parsed markdown section.
type Section struct {
	Level int    // Heading level (1-6), or 0 for content before the first heading.
	Title string // Heading text with leading/trailing whitespace trimmed.
	Body  string // Content between this heading and the next heading of equal or higher level.
}

// Document is a parsed markdown document split into sections.
type Document struct {
	sections []Section
}

// Parse splits a markdown string into sections by ATX-style headings (lines
// starting with one or more '#' characters). Content before the first heading
// is stored as a section with Level 0 and an empty Title.
func Parse(content string) *Document {
	lines := strings.Split(content, "\n")
	doc := &Document{}

	var cur *Section
	for _, line := range lines {
		if level, title, ok := parseHeading(line); ok {
			if cur != nil {
				cur.Body = strings.TrimRight(cur.Body, "\n")
				doc.sections = append(doc.sections, *cur)
			}
			cur = &Section{Level: level, Title: title}
			continue
		}
		if cur == nil {
			cur = &Section{} // level 0, preamble
		}
		cur.Body += line + "\n"
	}
	if cur != nil {
		cur.Body = strings.TrimRight(cur.Body, "\n")
		doc.sections = append(doc.sections, *cur)
	}

	return doc
}

// Sections returns all parsed sections.
func (d *Document) Sections() []Section {
	return d.sections
}

// Section returns the first section matching the given level and title.
// Title comparison is case-insensitive. Returns a zero-value Section if no match is found.
func (d *Document) Section(level int, title string) Section {
	for _, s := range d.sections {
		if s.Level == level && strings.EqualFold(s.Title, title) {
			return s
		}
	}
	return Section{}
}

// parseHeading returns the level and title for an ATX heading line, or ok=false.
func parseHeading(line string) (level int, title string, ok bool) {
	trimmed := strings.TrimLeft(line, " ")
	if len(trimmed) == 0 || trimmed[0] != '#' {
		return 0, "", false
	}
	i := 0
	for i < len(trimmed) && trimmed[i] == '#' {
		i++
	}
	if i > 6 {
		return 0, "", false
	}
	if i < len(trimmed) && trimmed[i] != ' ' && trimmed[i] != '\t' {
		return 0, "", false // e.g. "#notaheading"
	}
	title = strings.TrimSpace(trimmed[i:])
	// Strip optional closing hashes: "## Foo ##" -> "Foo"
	title = strings.TrimRight(title, "# ")
	return i, title, true
}
