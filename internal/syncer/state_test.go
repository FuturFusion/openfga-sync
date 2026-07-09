package syncer

import (
	"os"
	"reflect"
	"testing"
)

func TestStateRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	state, err := LoadState(dir)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(state.Targets) != 0 {
		t.Fatal("Expected an empty state")
	}

	tuples := []Tuple{
		{User: "user:alice@example.com", Relation: "user", Object: "project:app"},
	}

	err = state.SaveTarget("incus_cl001", tuples)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	err = state.SaveTarget("incus_cl002", tuples)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	reloaded, err := LoadState(dir)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !reflect.DeepEqual(reloaded.Targets, state.Targets) {
		t.Errorf("Unexpected state: %v", reloaded.Targets)
	}

	// Each store gets its own file.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("Unexpected state files: %v", entries)
	}

	// Removing a store only drops its own state.
	err = state.DeleteTarget("incus_cl001")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	reloaded, err = LoadState(dir)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(reloaded.Targets) != 1 || reloaded.Targets["incus_cl002"] == nil {
		t.Errorf("Unexpected state: %v", reloaded.Targets)
	}
}
