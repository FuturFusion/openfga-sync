package syncer

import (
	"fmt"
	"slices"

	"github.com/FuturFusion/openfga-sync/shared/config"
)

// Grant is a desired tuple scoped to a type of application and optionally
// to specific deployments of it.
type Grant struct {
	Tuple

	// Kind is the type of application ("incus", "operations-center",
	// "migration-manager") the grant applies to.
	Kind string `json:"kind"`

	// Targets restricts the grant to specific deployments (target
	// names). When empty, the grant is global to all deployments of
	// the application kind.
	Targets []string `json:"targets,omitempty"`
}

// Validate checks that the grant is well formed.
func (g Grant) Validate() error {
	if !slices.Contains(config.ApplicationKinds, g.Kind) {
		return fmt.Errorf("grant %s has unsupported kind %q", g.Tuple, g.Kind)
	}

	return g.Tuple.Validate()
}

// AppliesTo checks whether the grant applies to the given target.
func (g Grant) AppliesTo(kind string, target string) bool {
	if g.Kind != kind {
		return false
	}

	if len(g.Targets) == 0 {
		return true
	}

	return slices.Contains(g.Targets, target)
}
