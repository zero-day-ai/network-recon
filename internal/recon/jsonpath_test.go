package recon

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractJSONPath(t *testing.T) {
	// Test data structure
	data := map[string]any{
		"name": "test",
		"port": 8080,
		"nested": map[string]any{
			"field":  "value",
			"number": 42,
			"deep": map[string]any{
				"value": "deeply nested",
			},
		},
		"array": []any{
			"first",
			"second",
			"third",
		},
		"objects": []any{
			map[string]any{"id": 1, "name": "obj1"},
			map[string]any{"id": 2, "name": "obj2"},
		},
		"parent": map[string]any{
			"field": "parent value",
		},
	}

	tests := []struct {
		name     string
		data     map[string]any
		path     string
		expected any
	}{
		{
			name:     "simple field access",
			data:     data,
			path:     "$.name",
			expected: "test",
		},
		{
			name:     "simple field access without prefix",
			data:     data,
			path:     "name",
			expected: "test",
		},
		{
			name:     "numeric field access",
			data:     data,
			path:     "$.port",
			expected: 8080,
		},
		{
			name:     "nested field access",
			data:     data,
			path:     "$.nested.field",
			expected: "value",
		},
		{
			name:     "nested numeric field",
			data:     data,
			path:     "$.nested.number",
			expected: 42,
		},
		{
			name:     "deeply nested field",
			data:     data,
			path:     "$.nested.deep.value",
			expected: "deeply nested",
		},
		{
			name:     "array index access",
			data:     data,
			path:     "$.array[0]",
			expected: "first",
		},
		{
			name:     "array index access middle",
			data:     data,
			path:     "$.array[1]",
			expected: "second",
		},
		{
			name:     "array index access last",
			data:     data,
			path:     "$.array[2]",
			expected: "third",
		},
		{
			name:     "array of objects with field access",
			data:     data,
			path:     "$.objects[0]",
			expected: map[string]any{"id": 1, "name": "obj1"},
		},
		{
			name:     "parent field access",
			data:     data,
			path:     "$.parent.field",
			expected: "parent value",
		},
		{
			name:     "missing field returns nil",
			data:     data,
			path:     "$.missing",
			expected: nil,
		},
		{
			name:     "missing nested field returns nil",
			data:     data,
			path:     "$.nested.missing",
			expected: nil,
		},
		{
			name:     "missing deeply nested field returns nil",
			data:     data,
			path:     "$.nested.deep.missing",
			expected: nil,
		},
		{
			name:     "array index out of bounds returns nil",
			data:     data,
			path:     "$.array[10]",
			expected: nil,
		},
		{
			name:     "negative array index returns nil",
			data:     data,
			path:     "$.array[-1]",
			expected: nil,
		},
		{
			name:     "array access on non-array returns nil",
			data:     data,
			path:     "$.name[0]",
			expected: nil,
		},
		{
			name:     "invalid bracket notation returns nil",
			data:     data,
			path:     "$.array[0",
			expected: nil,
		},
		{
			name:     "invalid array index returns nil",
			data:     data,
			path:     "$.array[invalid]",
			expected: nil,
		},
		{
			name:     "empty path returns nil",
			data:     data,
			path:     "",
			expected: nil,
		},
		{
			name:     "only prefix returns nil",
			data:     data,
			path:     "$.",
			expected: nil,
		},
		{
			name:     "nil data returns nil",
			data:     nil,
			path:     "$.field",
			expected: nil,
		},
		{
			name:     "empty data returns nil",
			data:     map[string]any{},
			path:     "$.field",
			expected: nil,
		},
		{
			name:     "path with empty segment returns nil",
			data:     data,
			path:     "$.nested..field",
			expected: nil,
		},
		{
			name:     "navigate through non-map returns nil",
			data:     data,
			path:     "$.name.field",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractJSONPath(tt.data, tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractJSONPath_ComplexScenarios(t *testing.T) {
	t.Run("nested array access", func(t *testing.T) {
		data := map[string]any{
			"services": []any{
				map[string]any{
					"name":  "web",
					"ports": []any{80, 443},
				},
				map[string]any{
					"name":  "db",
					"ports": []any{5432},
				},
			},
		}

		// Access first service
		result := extractJSONPath(data, "$.services[0]")
		expected := map[string]any{
			"name":  "web",
			"ports": []any{80, 443},
		}
		assert.Equal(t, expected, result)

		// Access second service
		result = extractJSONPath(data, "$.services[1]")
		expected = map[string]any{
			"name":  "db",
			"ports": []any{5432},
		}
		assert.Equal(t, expected, result)
	})

	t.Run("deeply nested with arrays", func(t *testing.T) {
		data := map[string]any{
			"level1": map[string]any{
				"level2": map[string]any{
					"items": []any{
						map[string]any{"value": "target"},
					},
				},
			},
		}

		result := extractJSONPath(data, "$.level1.level2.items[0]")
		expected := map[string]any{"value": "target"}
		assert.Equal(t, expected, result)
	})

	t.Run("taxonomy parent reference pattern", func(t *testing.T) {
		// Simulating a taxonomy structure where we might reference parent
		data := map[string]any{
			"taxonomy": map[string]any{
				"category": "network",
				"parent": map[string]any{
					"name": "infrastructure",
					"id":   "infra-001",
				},
			},
		}

		result := extractJSONPath(data, "$.taxonomy.parent.name")
		assert.Equal(t, "infrastructure", result)

		result = extractJSONPath(data, "$.taxonomy.parent.id")
		assert.Equal(t, "infra-001", result)
	})

	t.Run("port and service structure", func(t *testing.T) {
		// Realistic port scan data structure
		data := map[string]any{
			"target": "192.168.1.1",
			"ports": []any{
				map[string]any{
					"number":  80,
					"state":   "open",
					"service": "http",
				},
				map[string]any{
					"number":  443,
					"state":   "open",
					"service": "https",
				},
			},
		}

		// Access first port object
		result := extractJSONPath(data, "$.ports[0]")
		expected := map[string]any{
			"number":  80,
			"state":   "open",
			"service": "http",
		}
		assert.Equal(t, expected, result)

		// Access target
		result = extractJSONPath(data, "$.target")
		assert.Equal(t, "192.168.1.1", result)
	})
}

func TestExtractJSONPath_EdgeCases(t *testing.T) {
	t.Run("single character field names", func(t *testing.T) {
		data := map[string]any{
			"a": map[string]any{
				"b": map[string]any{
					"c": "value",
				},
			},
		}

		result := extractJSONPath(data, "$.a.b.c")
		assert.Equal(t, "value", result)
	})

	t.Run("numeric string field names", func(t *testing.T) {
		data := map[string]any{
			"123": "numeric field",
		}

		result := extractJSONPath(data, "$.123")
		assert.Equal(t, "numeric field", result)
	})

	t.Run("special characters in field names", func(t *testing.T) {
		data := map[string]any{
			"field-name": "hyphenated",
			"field_name": "underscored",
		}

		result := extractJSONPath(data, "$.field-name")
		assert.Equal(t, "hyphenated", result)

		result = extractJSONPath(data, "$.field_name")
		assert.Equal(t, "underscored", result)
	})

	t.Run("zero index array access", func(t *testing.T) {
		data := map[string]any{
			"items": []any{"zero", "one", "two"},
		}

		result := extractJSONPath(data, "$.items[0]")
		assert.Equal(t, "zero", result)
	})

	t.Run("empty array", func(t *testing.T) {
		data := map[string]any{
			"empty": []any{},
		}

		result := extractJSONPath(data, "$.empty[0]")
		assert.Nil(t, result)
	})

	t.Run("boolean and null values", func(t *testing.T) {
		data := map[string]any{
			"enabled":  true,
			"disabled": false,
			"nullable": nil,
		}

		result := extractJSONPath(data, "$.enabled")
		assert.Equal(t, true, result)

		result = extractJSONPath(data, "$.disabled")
		assert.Equal(t, false, result)

		result = extractJSONPath(data, "$.nullable")
		assert.Nil(t, result)
	})
}
