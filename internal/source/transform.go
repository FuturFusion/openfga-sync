package source

import (
	"strings"
)

// applyTransforms applies the configured transforms to a name.
func applyTransforms(transforms []string, name string) string {
	for _, transform := range transforms {
		switch transform {
		case "lower":
			name = strings.ToLower(name)

		case "upper":
			name = strings.ToUpper(name)

		default:
		}
	}

	return name
}
