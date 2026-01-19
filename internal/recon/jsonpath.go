package recon

import (
	"strconv"
	"strings"
)

// extractJSONPath extracts a value from nested data using a JSONPath-like expression.
// Supports:
//   - $.field - top-level field
//   - $.nested.field - dot notation for nested objects
//   - $.array[0] - array index access
//   - $.parent.field - parent context reference (for nested taxonomies)
//
// Returns nil if the path does not exist or cannot be resolved.
func extractJSONPath(data map[string]any, path string) any {
	if data == nil || path == "" {
		return nil
	}

	// Remove "$." prefix if present
	path = strings.TrimPrefix(path, "$.")
	if path == "" {
		return nil
	}

	// Split path by dots
	segments := strings.Split(path, ".")

	var current any = data

	for _, segment := range segments {
		if segment == "" {
			return nil
		}

		// Check if this segment has array bracket notation
		arrayIndex := -1
		fieldName := segment

		if bracketIdx := strings.Index(segment, "["); bracketIdx != -1 {
			if !strings.HasSuffix(segment, "]") {
				return nil // Invalid bracket notation
			}

			fieldName = segment[:bracketIdx]
			indexStr := segment[bracketIdx+1 : len(segment)-1]

			var err error
			arrayIndex, err = strconv.Atoi(indexStr)
			if err != nil || arrayIndex < 0 {
				return nil // Invalid array index
			}
		}

		// Navigate to the field
		switch v := current.(type) {
		case map[string]any:
			val, exists := v[fieldName]
			if !exists {
				return nil
			}
			current = val
		default:
			// Can't navigate further if current is not a map
			return nil
		}

		// If array index was specified, access it
		if arrayIndex >= 0 {
			switch arr := current.(type) {
			case []any:
				if arrayIndex >= len(arr) {
					return nil // Index out of bounds
				}
				current = arr[arrayIndex]
			default:
				return nil // Field is not an array
			}
		}
	}

	return current
}
