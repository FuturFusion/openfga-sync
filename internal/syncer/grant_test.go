package syncer

import (
	"testing"
)

func TestGrantAppliesTo(t *testing.T) {
	t.Parallel()

	global := Grant{Tuple: Tuple{User: "user:a", Relation: "viewer", Object: "server:incus"}, Kind: "incus"}
	specific := Grant{Tuple: Tuple{User: "user:a", Relation: "admin", Object: "server:incus"}, Kind: "incus", Targets: []string{"cl001"}}

	if !global.AppliesTo("incus", "cl001") || !global.AppliesTo("incus", "cl002") {
		t.Error("Global grant should apply to all deployments of its kind")
	}

	if global.AppliesTo("operations-center", "cl001") {
		t.Error("Grant shouldn't apply to another kind")
	}

	if !specific.AppliesTo("incus", "cl001") || specific.AppliesTo("incus", "cl002") {
		t.Error("Specific grant should only apply to its deployments")
	}
}

func TestGrantValidate(t *testing.T) {
	t.Parallel()

	valid := Grant{Tuple: Tuple{User: "user:a", Relation: "viewer", Object: "server:incus"}, Kind: "incus"}

	err := valid.Validate()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	invalid := Grant{Tuple: Tuple{User: "user:a", Relation: "viewer", Object: "server:incus"}, Kind: "unknown"}

	err = invalid.Validate()
	if err == nil {
		t.Error("Expected an error")
	}
}
