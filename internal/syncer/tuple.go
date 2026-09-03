package syncer

import (
	"fmt"
	"slices"
	"strings"
)

// Tuple represents a single OpenFGA relationship tuple.
type Tuple struct {
	User     string `json:"user"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

// String implements fmt.Stringer for Tuple.
func (t Tuple) String() string {
	return fmt.Sprintf("(%s, %s, %s)", t.User, t.Relation, t.Object)
}

// Validate checks that the tuple is well formed.
func (t Tuple) Validate() error {
	if slices.Contains([]string{t.User, t.Relation, t.Object}, "") {
		return fmt.Errorf("tuple %s has an empty field", t)
	}

	if !strings.Contains(t.User, ":") {
		return fmt.Errorf("tuple %s has an invalid user", t)
	}

	objectType, _, ok := strings.Cut(t.Object, ":")
	if !ok || objectType == "" {
		return fmt.Errorf("tuple %s has an invalid object", t)
	}

	return nil
}

// ObjectUser returns the OpenFGA object for a user name, matching the
// encoding used by Incus (forward slashes are escaped).
func ObjectUser(name string) string {
	return "user:" + escape(name)
}

// ObjectGroup returns the OpenFGA object for a group name.
func ObjectGroup(name string) string {
	return "group:" + escape(name)
}

// groupReference returns the group name a tuple user refers to, if any
// (the "group:NAME#member" user set form).
func groupReference(user string) (string, bool) {
	name, ok := strings.CutPrefix(user, "group:")
	if !ok {
		return "", false
	}

	name, ok = strings.CutSuffix(name, "#member")
	if !ok {
		return "", false
	}

	return unescape(name), true
}

// groupMembership returns the group a tuple makes its user a member of, if
// any (the "member" relation on a "group:NAME" object).
func groupMembership(t Tuple) (string, bool) {
	if t.Relation != "member" {
		return "", false
	}

	name, ok := strings.CutPrefix(t.Object, "group:")
	if !ok {
		return "", false
	}

	return unescape(name), true
}

// objectType returns the type part of an OpenFGA object.
func objectType(object string) string {
	t, _, _ := strings.Cut(object, ":")

	return t
}

// objectProject returns the project an object belongs to, if any.
// Incus places the project name as the first path element of all
// project-scoped objects.
func objectProject(object string) string {
	objType, id, _ := strings.Cut(object, ":")

	switch objType {
	case "server", "certificate", "storage_pool", "network_integration", "user", "group":
		// Server-scoped object types.
		return ""

	case "project":
		return unescape(id)

	default:
		element, _, _ := strings.Cut(id, "/")

		return unescape(element)
	}
}

// escape replaces forward slashes with their URL encoding.
func escape(s string) string {
	return strings.ReplaceAll(s, "/", "%2F")
}

// unescape replaces only the escaped forward slashes.
func unescape(s string) string {
	return strings.ReplaceAll(s, "%2F", "/")
}
