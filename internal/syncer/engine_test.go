package syncer

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestComputeChanges(t *testing.T) {
	t.Parallel()

	alice := Tuple{User: "user:alice@example.com", Relation: "user", Object: "project:app-1234-stg"}
	bob := Tuple{User: "user:bob@example.com", Relation: "user", Object: "project:app-1234-stg"}
	carol := Tuple{User: "user:carol@example.com", Relation: "operator", Object: "project:app-1234-stg"}

	desired := map[Tuple]bool{alice: true, bob: true}

	// bob was already written by us, carol is no longer desired.
	// Tuples added by hand aren't tracked, so they're never touched.
	managed := map[Tuple]bool{bob: true, carol: true}

	writes, deletes := computeChanges(desired, managed)

	if !reflect.DeepEqual(writes, []Tuple{alice}) {
		t.Errorf("Unexpected writes: %v", writes)
	}

	if !reflect.DeepEqual(deletes, []Tuple{carol}) {
		t.Errorf("Unexpected deletes: %v", deletes)
	}
}

func TestComputeChangesAuthoritative(t *testing.T) {
	t.Parallel()

	alice := Tuple{User: "user:alice@example.com", Relation: "user", Object: "project:app"}
	manual := Tuple{User: "user:admin@example.com", Relation: "admin", Object: "server:incus"}

	// In authoritative mode, the managed set is everything present in
	// the store, so unexpected tuples get deleted.
	writes, deletes := computeChanges(map[Tuple]bool{alice: true}, map[Tuple]bool{alice: true, manual: true})

	if len(writes) != 0 {
		t.Errorf("Unexpected writes: %v", writes)
	}

	if !reflect.DeepEqual(deletes, []Tuple{manual}) {
		t.Errorf("Unexpected deletes: %v", deletes)
	}
}

type fakeResolver struct {
	prefix string
}

func (*fakeResolver) Name() string {
	return "fake"
}

func (*fakeResolver) Groups(_ context.Context) (map[string][]string, error) {
	return map[string][]string{}, nil
}

func (r *fakeResolver) ManagesGroup(name string) bool {
	return strings.HasPrefix(name, r.prefix)
}

func TestAuthoritativeScope(t *testing.T) {
	t.Parallel()

	grant := Tuple{User: "user:alice@example.com", Relation: "admin", Object: "server:incus"}
	owned := Tuple{User: "user:alice@example.com", Relation: "member", Object: "group:nsec-admins"}
	foreign := Tuple{User: "user:bob@example.com", Relation: "member", Object: "group:other"}
	current := map[Tuple]bool{grant: true, owned: true, foreign: true}

	// Group resolver only: memberships of the matching groups are owned,
	// permission tuples are left alone.
	engine := &Engine{Resolvers: []GroupResolver{&fakeResolver{prefix: "nsec-"}}}

	managed := engine.authoritativeScope(current)
	if !reflect.DeepEqual(managed, map[Tuple]bool{owned: true}) {
		t.Errorf("Unexpected managed tuples: %v", managed)
	}

	// Grant sources only: permission tuples are owned, memberships aren't.
	engine = &Engine{Sources: []Source{nil}}

	managed = engine.authoritativeScope(current)
	if !reflect.DeepEqual(managed, map[Tuple]bool{grant: true}) {
		t.Errorf("Unexpected managed tuples: %v", managed)
	}
}

func TestComputeManaged(t *testing.T) {
	t.Parallel()

	alice := Tuple{User: "user:alice@example.com", Relation: "user", Object: "project:app"}
	bob := Tuple{User: "user:bob@example.com", Relation: "user", Object: "project:app"}
	carol := Tuple{User: "user:carol@example.com", Relation: "user", Object: "project:app"}
	dave := Tuple{User: "user:dave@example.com", Relation: "user", Object: "project:app"}

	// alice was already managed, bob was just written, carol was
	// successfully deleted and dave failed to delete.
	desired := map[Tuple]bool{alice: true, bob: true}
	managed := map[Tuple]bool{alice: true, carol: true, dave: true}

	newManaged := computeManaged(desired, managed, []Tuple{bob}, []Tuple{carol, dave}, []Tuple{carol})

	expected := []Tuple{alice, bob, dave}
	if !reflect.DeepEqual(newManaged, expected) {
		t.Errorf("Unexpected managed tuples: %v", newManaged)
	}
}

func TestObjectExists(t *testing.T) {
	t.Parallel()

	objects := map[string]bool{"project:app": true, "instance:app/vm01": true}

	for _, object := range []string{"server:incus", "group:admins", "user:alice", "project:app", "instance:app/vm01"} {
		if !objectExists(objects, object) {
			t.Errorf("Expected %q to exist", object)
		}
	}

	for _, object := range []string{"project:other", "instance:app/vm02", "storage_pool:local"} {
		if objectExists(objects, object) {
			t.Errorf("Expected %q to be missing", object)
		}
	}
}

func TestMatchObjects(t *testing.T) {
	t.Parallel()

	objects := map[string]bool{
		"project:foo":           true,
		"project:bar":           true,
		"instance:foo/i12345":   true,
		"instance:bar/i12345":   true,
		"instance:bar/i12346":   true,
		"instance:foo/x/i12345": true,
	}

	matches := matchObjects(objects, "instance:*/i12345")
	if !reflect.DeepEqual(matches, []string{"instance:bar/i12345", "instance:foo/i12345"}) {
		t.Errorf("Unexpected matches: %v", matches)
	}

	matches = matchObjects(objects, "instance:bar/*")
	if !reflect.DeepEqual(matches, []string{"instance:bar/i12345", "instance:bar/i12346"}) {
		t.Errorf("Unexpected matches: %v", matches)
	}

	matches = matchObjects(objects, "instance:*/i99999")
	if len(matches) != 0 {
		t.Errorf("Unexpected matches: %v", matches)
	}
}

func TestObjectUser(t *testing.T) {
	t.Parallel()

	user := ObjectUser("alice@example.com")
	if user != "user:alice@example.com" {
		t.Errorf("Unexpected user object: %q", user)
	}

	user = ObjectUser("weird/name")
	if user != "user:weird%2Fname" {
		t.Errorf("Unexpected user object: %q", user)
	}
}

func TestTupleValidate(t *testing.T) {
	t.Parallel()

	valid := Tuple{User: "user:alice", Relation: "user", Object: "project:app"}

	err := valid.Validate()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	invalid := []Tuple{
		{User: "", Relation: "user", Object: "project:app"},
		{User: "user:alice", Relation: "", Object: "project:app"},
		{User: "user:alice", Relation: "user", Object: "app"},
		{User: "alice", Relation: "user", Object: "project:app"},
	}

	for _, tuple := range invalid {
		err := tuple.Validate()
		if err == nil {
			t.Errorf("Expected an error for %s", tuple)
		}
	}
}
