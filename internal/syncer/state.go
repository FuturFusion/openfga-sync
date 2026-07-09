package syncer

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// State tracks the tuples that openfga-sync wrote to each store, one JSON
// file per store. Only tuples present in the state are ever considered for
// deletion, so tuples managed by the applications themselves or added
// manually are never touched.
type State struct {
	dir string

	// Targets maps a store name to the tuples managed on it.
	Targets map[string][]Tuple
}

// LoadState reads the per-store state files from the state directory,
// returning an empty state if the directory doesn't exist yet.
func LoadState(dir string) (*State, error) {
	state := &State{
		dir:     dir,
		Targets: map[string][]Tuple{},
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return state, nil
		}

		return nil, fmt.Errorf("failed to read state directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		content, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("failed to read state file %q: %w", entry.Name(), err)
		}

		tuples := []Tuple{}

		err = json.Unmarshal(content, &tuples)
		if err != nil {
			return nil, fmt.Errorf("failed to parse state file %q: %w", entry.Name(), err)
		}

		storeName, err := url.PathUnescape(strings.TrimSuffix(entry.Name(), ".json"))
		if err != nil {
			return nil, fmt.Errorf("failed to parse state file name %q: %w", entry.Name(), err)
		}

		state.Targets[storeName] = tuples
	}

	return state, nil
}

// SaveTarget writes the state file of a single store atomically.
func (s *State) SaveTarget(storeName string, tuples []Tuple) error {
	s.Targets[storeName] = tuples

	content, err := json.Marshal(tuples)
	if err != nil {
		return fmt.Errorf("failed to serialize state of store %q: %w", storeName, err)
	}

	err = os.MkdirAll(s.dir, 0o700)
	if err != nil {
		return fmt.Errorf("failed to create state directory: %w", err)
	}

	path := s.path(storeName)
	tmpPath := path + ".tmp"

	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to write state file: %w", err)
	}

	_, err = f.Write(content)
	if err != nil {
		_ = f.Close()

		return fmt.Errorf("failed to write state file: %w", err)
	}

	err = f.Sync()
	if err != nil {
		_ = f.Close()

		return fmt.Errorf("failed to sync state file: %w", err)
	}

	err = f.Close()
	if err != nil {
		return fmt.Errorf("failed to close state file: %w", err)
	}

	err = os.Rename(tmpPath, path)
	if err != nil {
		return fmt.Errorf("failed to rename state file: %w", err)
	}

	return s.syncDir()
}

// DeleteTarget removes the state of a store.
func (s *State) DeleteTarget(storeName string) error {
	delete(s.Targets, storeName)

	err := os.Remove(s.path(storeName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}

		return fmt.Errorf("failed to remove state file of store %q: %w", storeName, err)
	}

	return s.syncDir()
}

// path returns the state file path of a store.
func (s *State) path(storeName string) string {
	return filepath.Join(s.dir, url.PathEscape(storeName)+".json")
}

// syncDir flushes the state directory itself.
func (s *State) syncDir() error {
	dir, err := os.Open(s.dir)
	if err != nil {
		return fmt.Errorf("failed to open state directory: %w", err)
	}

	defer dir.Close()

	err = dir.Sync()
	if err != nil {
		return fmt.Errorf("failed to sync state directory: %w", err)
	}

	return nil
}
