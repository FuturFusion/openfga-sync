package source

import (
	"net"
	"reflect"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/FuturFusion/openfga-sync/shared/config"
)

func TestMapName(t *testing.T) {
	t.Parallel()

	roles, err := compileRoles([]config.Role{
		{Pattern: "^app-(?P<app>.+)-admin$", Grants: []config.RoleGrant{
			{Relation: "operator", Object: "project:app-${app}-stg", Type: "incus"},
			{Relation: "viewer", Object: "project:app-${app}-prod", Type: "incus"},
		}},
		{Pattern: "^(?P<project>.+)-(?P<role>viewer)$", Grants: []config.RoleGrant{
			{Relation: "${role}", Object: "project:${project}", Type: "incus", Targets: []string{"cl001"}},
		}},
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// A single group grants multiple tuples through one role.
	grants := mapName(roles, "app-1234-admin")
	if len(grants) != 2 {
		t.Fatalf("Unexpected grants: %+v", grants)
	}

	if grants[0].Relation != "operator" || grants[0].Object != "project:app-1234-stg" {
		t.Errorf("Unexpected grant: %+v", grants[0])
	}

	if grants[1].Relation != "viewer" || grants[1].Object != "project:app-1234-prod" {
		t.Errorf("Unexpected grant: %+v", grants[1])
	}

	if grants[0].Kind != "incus" || len(grants[0].Targets) != 0 {
		t.Errorf("Unexpected grant scope: %+v", grants[0])
	}

	grants = mapName(roles, "app-1234-stg-viewer")
	if len(grants) != 1 || grants[0].Relation != "viewer" || grants[0].Object != "project:app-1234-stg" {
		t.Errorf("Unexpected grants: %+v", grants)
	}

	if len(grants[0].Targets) != 1 || grants[0].Targets[0] != "cl001" {
		t.Errorf("Unexpected grant scope: %+v", grants[0])
	}

	grants = mapName(roles, "unrelated-group")
	if len(grants) != 0 {
		t.Errorf("Unexpected grants: %+v", grants)
	}
}

func TestSRVURLs(t *testing.T) {
	t.Parallel()

	urls := srvURLs([]*net.SRV{
		{Target: "dc1.example.com.", Port: 389},
		{Target: "dc2.example.com.", Port: 3268},
		{Target: "", Port: 389},
	})

	expected := []string{"ldap://dc1.example.com:389", "ldap://dc2.example.com:3268"}
	if !reflect.DeepEqual(urls, expected) {
		t.Errorf("Unexpected URLs: %v", urls)
	}
}

func TestMemberName(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"CN=jdoe,OU=Users,DC=example,DC=com":        "jdoe",
		"cn=John Doe,ou=Users,dc=example,dc=com":    "John Doe",
		"CN=Doe\\, John,OU=Users,DC=example,DC=com": "Doe, John",
		"jdoe": "jdoe",
	}

	for member, expected := range cases {
		name := memberName(member)
		if name != expected {
			t.Errorf("Unexpected name for %q: %q", member, name)
		}
	}
}

func TestRangeEnd(t *testing.T) {
	t.Parallel()

	end, final := rangeEnd("member;range=0-1499")
	if final || end != 1499 {
		t.Errorf("Unexpected result: %d %v", end, final)
	}

	end, final = rangeEnd("member;range=1500-2999")
	if final || end != 2999 {
		t.Errorf("Unexpected result: %d %v", end, final)
	}

	_, final = rangeEnd("member;range=3000-*")
	if !final {
		t.Error("Expected the final chunk")
	}
}

func TestMembers(t *testing.T) {
	t.Parallel()

	src := NewLDAP("test", &config.LDAPSource{MemberAttribute: "member"})

	// Small group, all members in the plain attribute.
	members, err := src.members(nil, "CN=g1,DC=example,DC=com", []*ldap.EntryAttribute{
		{Name: "member", Values: []string{"CN=a,DC=example,DC=com", "CN=b,DC=example,DC=com"}},
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(members) != 2 {
		t.Errorf("Unexpected members: %v", members)
	}

	// Final ranged chunk (no follow-up query needed).
	members, err = src.members(nil, "CN=g2,DC=example,DC=com", []*ldap.EntryAttribute{
		{Name: "member;range=1500-*", Values: []string{"CN=c,DC=example,DC=com"}},
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(members) != 1 || members[0] != "CN=c,DC=example,DC=com" {
		t.Errorf("Unexpected members: %v", members)
	}
}

func TestCompileRolesInvalid(t *testing.T) {
	t.Parallel()

	_, err := compileRoles([]config.Role{{Pattern: "([", Grants: []config.RoleGrant{{Relation: "user"}}}})
	if err == nil {
		t.Error("Expected an error")
	}
}
