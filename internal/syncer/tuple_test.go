package syncer

import (
	"testing"
)

func TestGroupReference(t *testing.T) {
	t.Parallel()

	name, ok := groupReference("group:app-admins#member")
	if !ok || name != "app-admins" {
		t.Errorf("Unexpected reference: %q %v", name, ok)
	}

	name, ok = groupReference("group:weird%2Fname#member")
	if !ok || name != "weird/name" {
		t.Errorf("Unexpected reference: %q %v", name, ok)
	}

	for _, user := range []string{"user:alice@example.com", "group:app-admins", "server:incus", "user:*"} {
		_, ok := groupReference(user)
		if ok {
			t.Errorf("Unexpected group reference for %q", user)
		}
	}
}
