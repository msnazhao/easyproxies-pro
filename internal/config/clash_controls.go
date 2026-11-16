package config

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// A private-use marker keeps the YAML structure intact while the standard
// parser locates damaged entries. Never repair connection fields with it.
func maskClashControls(content string) (string, rune, int, error) {
	if !utf8.ValidString(content) {
		return "", 0, 0, fmt.Errorf("invalid UTF-8 in clash subscription")
	}
	count := 0
	privateUse := make(map[rune]bool)
	for _, r := range content {
		if forbiddenYAMLCharacter(r) {
			count++
		}
		if r >= 0xE000 && r <= 0xF8FF {
			privateUse[r] = true
		}
	}
	if count == 0 {
		return content, 0, 0, nil
	}
	// Reserve escaped private-use characters too, since YAML decodes them
	// after marker selection. A valid escaped password must not look damaged.
	for i := 0; i+1 < len(content); i++ {
		if content[i] != '\\' {
			continue
		}
		width := 0
		switch content[i+1] {
		case 'u':
			width = 4
		case 'U':
			width = 8
		}
		if width == 0 || i+2+width > len(content) {
			continue
		}
		if value, err := strconv.ParseUint(content[i+2:i+2+width], 16, 32); err == nil && value >= 0xE000 && value <= 0xF8FF {
			privateUse[rune(value)] = true
		}
	}
	var marker rune
	for r := rune(0xE000); r <= 0xF8FF; r++ {
		if !privateUse[r] {
			marker = r
			break
		}
	}
	if marker == 0 {
		return "", 0, 0, fmt.Errorf("cannot safely isolate invalid clash characters")
	}
	return strings.Map(func(r rune) rune {
		if forbiddenYAMLCharacter(r) {
			return marker
		}
		return r
	}, content), marker, count, nil
}

func forbiddenYAMLCharacter(r rune) bool {
	return r < 0x20 && r != '\t' && r != '\n' && r != '\r' || r >= 0x7F && r <= 0x9F && r != 0x85 || r == 0xFFFE || r == 0xFFFF
}

func damagedClashValue(node *yaml.Node, marker rune, seen map[*yaml.Node]bool) bool {
	return clashExpansionCost(node, marker, seen, make(map[*yaml.Node]clashCost)).unsafe()
}

const maxClashExpandedNodes = 4096
const maxClashExpandedBytes = 256 << 10

type clashCost struct{ nodes, bytes int }

func (c clashCost) unsafe() bool {
	return c.nodes > maxClashExpandedNodes || c.bytes > maxClashExpandedBytes
}
func unsafeClashCost() clashCost {
	return clashCost{maxClashExpandedNodes + 1, maxClashExpandedBytes + 1}
}

// Memoized costs count alias expansion without actually expanding the graph.
// Reject cycles and non-text tags before Decode can reinterpret scalar bytes.
func clashExpansionCost(node *yaml.Node, marker rune, visiting map[*yaml.Node]bool, costs map[*yaml.Node]clashCost) clashCost {
	if node == nil {
		return clashCost{}
	}
	if visiting[node] {
		return unsafeClashCost()
	}
	if len(visiting) >= 128 {
		return unsafeClashCost()
	}
	if cost, ok := costs[node]; ok {
		return cost
	}
	switch node.Tag {
	case "", "!!map", "!!seq", "!!str", "!!int", "!!float", "!!bool", "!!null", "!!timestamp", "!!merge":
	default:
		return unsafeClashCost()
	}
	for _, r := range node.Value {
		if unicode.IsControl(r) || marker != 0 && r == marker {
			return unsafeClashCost()
		}
	}
	visiting[node] = true
	defer delete(visiting, node)
	total := clashCost{1, len(node.Value)}
	if total.unsafe() {
		return unsafeClashCost()
	}
	for _, child := range node.Content {
		childCost := clashExpansionCost(child, marker, visiting, costs)
		total.nodes += childCost.nodes
		total.bytes += childCost.bytes
		if total.unsafe() {
			return unsafeClashCost()
		}
	}
	aliasCost := clashExpansionCost(node.Alias, marker, visiting, costs)
	total.nodes += aliasCost.nodes
	total.bytes += aliasCost.bytes
	if total.unsafe() {
		return unsafeClashCost()
	}
	costs[node] = total
	return total
}

// Only the display-name scalar may be cleaned. Corruption anywhere else,
// including unknown fields, mapping keys or alias targets, rejects the entry.
func cleanClashDisplayName(node *yaml.Node, marker rune) {
	if node.Kind != yaml.MappingNode {
		return
	}
	// Alias targets may share these nodes with connection fields. Copy before
	// cleaning a display name so an anchored password is never modified.
	node.Content = append([]*yaml.Node(nil), node.Content...)
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Value == "name" && value.Kind == yaml.ScalarNode && value.Tag == "!!str" {
			copyValue := *value
			value = &copyValue
			node.Content[i+1] = value
			value.Value = strings.Map(func(r rune) rune {
				if unicode.IsControl(r) || marker != 0 && r == marker {
					return -1
				}
				return r
			}, value.Value)
		}
	}
}
