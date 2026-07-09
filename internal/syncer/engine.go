// Package syncer implements the OpenFGA tuple synchronization engine.
package syncer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
)

// Source is a provider of desired OpenFGA grants.
type Source interface {
	// Name returns the source name.
	Name() string

	// Grants returns the full set of grants the source wants applied.
	Grants(ctx context.Context) ([]Grant, error)
}

// GroupResolver is a provider of group membership, used to fill in the
// members of OpenFGA groups that were granted access by a third party.
type GroupResolver interface {
	// Name returns the resolver name.
	Name() string

	// Groups returns the membership of all the known groups, as a map
	// of group name to the user names of its members.
	Groups(ctx context.Context) (map[string][]string, error)
}

// Engine drives the synchronization of all sources into all stores.
type Engine struct {
	Sources   []Source
	Resolvers []GroupResolver
	Instance  *Instance
	State     *State
	DryRun    bool

	// Authoritative makes openfga-sync the owner of all user permission
	// tuples: instead of tracking its own tuples in the state files, it
	// compares the desired grants with all the user tuples present in
	// each store and deletes anything unexpected.
	Authoritative bool

	// SkipMissingObjects only pushes tuples whose objects exist in the
	// store, skipping the others until a later pass where the objects
	// showed up.
	SkipMissingObjects bool
}

// Sync performs a single synchronization pass.
func (e *Engine) Sync(ctx context.Context) error {
	// Collect the desired grants from all sources. If any source fails,
	// the whole pass is aborted as an incomplete view would otherwise
	// cause the deletion of valid tuples.
	grants := []Grant{}

	for _, src := range e.Sources {
		srcGrants, err := src.Grants(ctx)
		if err != nil {
			return fmt.Errorf("failed to get grants from source %q: %w", src.Name(), err)
		}

		for _, grant := range srcGrants {
			err := grant.Validate()
			if err != nil {
				slog.Warn("Skipping invalid grant", slog.String("source", src.Name()), slog.Any("error", err))

				continue
			}

			grants = append(grants, grant)
		}

		slog.Debug("Fetched grants", slog.String("source", src.Name()), slog.Int("count", len(srcGrants)))
	}

	// Collect the group membership from all resolvers.
	membership := map[string][]string{}

	for _, resolver := range e.Resolvers {
		groups, err := resolver.Groups(ctx)
		if err != nil {
			return fmt.Errorf("failed to get groups from source %q: %w", resolver.Name(), err)
		}

		for name, members := range groups {
			membership[name] = append(membership[name], members...)
		}

		slog.Debug("Fetched groups", slog.String("source", resolver.Name()), slog.Int("count", len(groups)))
	}

	// Discover the stores to synchronize.
	targets, err := e.Instance.Targets(ctx)
	if err != nil {
		return err
	}

	// Prune the state of stores that no longer exist.
	if !e.Authoritative && !e.DryRun {
		storeNames := map[string]bool{}
		for _, target := range targets {
			storeNames[target.StoreName()] = true
		}

		for storeName := range e.State.Targets {
			if !storeNames[storeName] {
				slog.Info("Dropping state of removed store", slog.String("store", storeName))

				err := e.State.DeleteTarget(storeName)
				if err != nil {
					return err
				}
			}
		}
	}

	// Synchronize each store independently.
	errs := []error{}

	for _, target := range targets {
		err := e.syncTarget(ctx, target, grants, membership)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to sync store %q: %w", target.StoreName(), err))
		}
	}

	return errors.Join(errs...)
}

func (e *Engine) syncTarget(ctx context.Context, target *Target, grants []Grant, membership map[string][]string) error {
	// Select the grants that apply to this target.
	desired := map[Tuple]bool{}

	for _, grant := range grants {
		if grant.AppliesTo(target.Kind(), target.Name()) {
			desired[grant.Tuple] = true
		}
	}

	// On Incus stores, filter the desired tuples down to objects that
	// exist on this deployment. The other application kinds use flat
	// models without object tuples to check against.
	filtered := desired

	if e.SkipMissingObjects && target.Kind() == "incus" {
		projects, err := target.ExistingProjects(ctx)
		if err != nil {
			return err
		}

		filtered = map[Tuple]bool{}
		objectCache := map[string]bool{}

		for tuple := range desired {
			exists, err := objectExists(ctx, target, projects, objectCache, tuple.Object)
			if err != nil {
				return err
			}

			if !exists {
				slog.Debug("Skipping tuple for missing object", slog.String("store", target.StoreName()), slog.String("object", tuple.Object))

				continue
			}

			filtered[tuple] = true
		}
	}

	// Fill in the membership of the groups that were granted access in
	// the store, based on the group membership from the resolvers.
	if len(e.Resolvers) > 0 {
		groups, err := target.ReferencedGroups(ctx)
		if err != nil {
			return err
		}

		for _, group := range groups {
			members, ok := membership[group]
			if !ok {
				slog.Warn("Store grants access to an unknown group", slog.String("store", target.StoreName()), slog.String("group", group))

				continue
			}

			for _, member := range members {
				filtered[Tuple{User: ObjectUser(member), Relation: "member", Object: ObjectGroup(group)}] = true
			}
		}
	}

	// Get the set of tuples we're reconciling against. In authoritative
	// mode that's every user permission tuple present in the store, so
	// anything unexpected gets deleted. Otherwise it's the record of the
	// tuples openfga-sync itself wrote, so other tuples are never touched.
	var managed map[Tuple]bool

	if e.Authoritative {
		var err error

		managed, err = target.UserTuples(ctx)
		if err != nil {
			return err
		}
	} else {
		managed = map[Tuple]bool{}
		for _, tuple := range e.State.Targets[target.StoreName()] {
			managed[tuple] = true
		}
	}

	// Compute the changes.
	writes, deletes := computeChanges(filtered, managed)

	if e.DryRun {
		for _, tuple := range writes {
			slog.Info("Would write tuple", slog.String("store", target.StoreName()), slog.String("tuple", tuple.String()))
		}

		for _, tuple := range deletes {
			slog.Info("Would delete tuple", slog.String("store", target.StoreName()), slog.String("tuple", tuple.String()))
		}

		return nil
	}

	if len(writes) == 0 && len(deletes) == 0 {
		return nil
	}

	appliedWrites, appliedDeletes, applyErr := target.Apply(ctx, writes, deletes)

	if !e.Authoritative {
		err := e.State.SaveTarget(target.StoreName(), computeManaged(filtered, managed, appliedWrites, deletes, appliedDeletes))
		if err != nil {
			return errors.Join(applyErr, err)
		}
	}

	slog.Info("Synchronized store", slog.String("store", target.StoreName()), slog.Int("writes", len(appliedWrites)), slog.Int("deletes", len(appliedDeletes)))

	return applyErr
}

// objectExists checks whether the object referenced by a tuple exists on the
// target, using the object tuples managed by Incus itself.
func objectExists(ctx context.Context, target *Target, projects map[string]bool, cache map[string]bool, object string) (bool, error) {
	objType := objectType(object)

	// The server object always exists and groups/users have no anchor
	// tuples to check for.
	if objType == "server" || objType == "group" || objType == "user" {
		return true, nil
	}

	// Projects are checked against the project list.
	if objType == "project" {
		return projects[objectProject(object)], nil
	}

	// Any other project-scoped object first gets its project checked.
	project := objectProject(object)
	if project != "" && !projects[project] {
		return false, nil
	}

	// Then the object itself is checked for its anchor tuple.
	exists, ok := cache[object]
	if ok {
		return exists, nil
	}

	exists, err := target.ObjectExists(ctx, object)
	if err != nil {
		return false, err
	}

	cache[object] = exists

	return exists, nil
}

// computeChanges compares the desired tuples with the managed ones: new
// tuples get written, tuples that are no longer desired get deleted.
func computeChanges(desired map[Tuple]bool, managed map[Tuple]bool) ([]Tuple, []Tuple) {
	writes := []Tuple{}

	for tuple := range desired {
		if !managed[tuple] {
			writes = append(writes, tuple)
		}
	}

	deletes := []Tuple{}

	for tuple := range managed {
		if !desired[tuple] {
			deletes = append(deletes, tuple)
		}
	}

	sortTuples(writes)
	sortTuples(deletes)

	return writes, deletes
}

// computeManaged returns the new set of managed tuples for a store: the
// tuples that were already managed and are still desired, the successful
// writes and any tuple which failed to delete (so deletion is retried on
// the next pass).
func computeManaged(desired map[Tuple]bool, managed map[Tuple]bool, appliedWrites []Tuple, deletes []Tuple, appliedDeletes []Tuple) []Tuple {
	newManaged := map[Tuple]bool{}

	for tuple := range desired {
		if managed[tuple] {
			newManaged[tuple] = true
		}
	}

	for _, tuple := range appliedWrites {
		newManaged[tuple] = true
	}

	deleted := map[Tuple]bool{}
	for _, tuple := range appliedDeletes {
		deleted[tuple] = true
	}

	for _, tuple := range deletes {
		if !deleted[tuple] {
			newManaged[tuple] = true
		}
	}

	tuples := make([]Tuple, 0, len(newManaged))
	for tuple := range newManaged {
		tuples = append(tuples, tuple)
	}

	sortTuples(tuples)

	return tuples
}

func sortTuples(tuples []Tuple) {
	slices.SortFunc(tuples, func(a Tuple, b Tuple) int {
		return strings.Compare(
			strings.Join([]string{a.Object, a.Relation, a.User}, "\x00"),
			strings.Join([]string{b.Object, b.Relation, b.User}, "\x00"),
		)
	})
}
