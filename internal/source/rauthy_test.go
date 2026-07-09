package source

import (
	"encoding/json"
	"testing"
)

func TestParseRoleMeta(t *testing.T) {
	t.Parallel()

	meta := json.RawMessage(`{"openfga": {
	    "incus": {
	        "global": [
	            {"relation": "viewer", "object": "server:incus"},
	            {"relation": "operator", "object": "project:bar"}
	        ],
	        "specific": {
	            "cl001": [{"relation": "admin"}],
	            "cl002": [
	                {"relation": "operator", "object": "project:foo"},
	                {"relation": "user", "object": "instance:baz/blah"}
	            ]
	        }
	    },
	    "operations-center": {
	        "global": [{"relation": "viewer", "object": "server:operations-center"}],
	        "specific": {
	            "operations-center01": [{"relation": "admin", "object": "server:operations-center"}]
	        }
	    },
	    "migration-manager": {
	        "global": [{"relation": "viewer", "object": "server:migration-manager"}],
	        "specific": {
	            "migration-manager01": [{"relation": "admin", "object": "server:migration-manager"}]
	        }
	    }
	}}`)

	grants, err := parseRoleMeta(meta)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(grants) != 9 {
		t.Fatalf("Unexpected grant count: %d", len(grants))
	}

	counts := map[string]int{}

	for _, grant := range grants {
		key := grant.Kind
		if len(grant.Targets) > 0 {
			key += "/" + grant.Targets[0]
		}

		counts[key]++

		// Omitted objects default to the kind's server object.
		if key == "incus/cl001" && grant.Object != "server:incus" {
			t.Errorf("Unexpected default object: %q", grant.Object)
		}
	}

	expected := map[string]int{
		"incus":                                 2,
		"incus/cl001":                           1,
		"incus/cl002":                           2,
		"operations-center":                     1,
		"operations-center/operations-center01": 1,
		"migration-manager":                     1,
		"migration-manager/migration-manager01": 1,
	}

	for key, count := range expected {
		if counts[key] != count {
			t.Errorf("Unexpected count for %q: %d", key, counts[key])
		}
	}

	// Unrelated metadata.
	grants, err = parseRoleMeta(json.RawMessage(`{"something": "else"}`))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(grants) != 0 {
		t.Errorf("Unexpected grants: %+v", grants)
	}

	// Invalid metadata.
	_, err = parseRoleMeta(json.RawMessage(`"just a string"`))
	if err == nil {
		t.Error("Expected an error")
	}

	_, err = parseRoleMeta(json.RawMessage(`{"openfga": [{"relation": "user", "object": "project:app"}]}`))
	if err == nil {
		t.Error("Expected an error for the legacy array format")
	}
}
