package source

import (
	"fmt"
	"regexp"

	"github.com/FuturFusion/openfga-sync/internal/syncer"
	"github.com/FuturFusion/openfga-sync/shared/config"
)

// compiledRole is a compiled role definition.
type compiledRole struct {
	pattern *regexp.Regexp
	grants  []config.RoleGrant
}

// compileRoles compiles the configured role patterns.
func compileRoles(cfgs []config.Role) ([]compiledRole, error) {
	roles := make([]compiledRole, 0, len(cfgs))
	for _, role := range cfgs {
		pattern, err := regexp.Compile(role.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid pattern %q: %w", role.Pattern, err)
		}

		roles = append(roles, compiledRole{pattern: pattern, grants: role.Grants})
	}

	return roles, nil
}

// mapName returns the grants of the roles matching a name (LDAP group name,
// Zitadel role key), with the user left empty. Capture groups from the role
// pattern can be referenced in both the relation and the object templates.
func mapName(roles []compiledRole, name string) []syncer.Grant {
	grants := []syncer.Grant{}

	for _, role := range roles {
		match := role.pattern.FindStringSubmatchIndex(name)
		if match == nil {
			continue
		}

		for _, grant := range role.grants {
			grants = append(grants, syncer.Grant{
				Tuple: syncer.Tuple{
					Relation: string(role.pattern.ExpandString(nil, grant.Relation, name, match)),
					Object:   string(role.pattern.ExpandString(nil, grant.Object, name, match)),
				},
				Kind:    grant.Type,
				Targets: grant.Targets,
			})
		}
	}

	return grants
}
