// Package syncer implements the OpenFGA tuple synchronization engine.
package syncer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
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

	// ManagesGroup reports whether a group falls within the resolver's
	// scope. Groups outside of it are left alone.
	ManagesGroup(name string) bool
}

// Engine drives the synchronization of all sources into all stores.
type Engine struct {
	Sources   []Source
	Resolvers []GroupResolver
	Instance  *Instance
	State     *State
	DryRun    bool

	// Authoritative makes openfga-sync the owner of the user tuples in
	// its scope: instead of tracking its own tuples in the state files,
	// it compares the desired tuples with those present in each store
	// and deletes anything unexpected. The scope covers the permission
	// tuples when sources are configured and the membership of the
	// groups managed by the resolvers.
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

			// Wildcards expand against the objects found in the store,
			// which is only known for Incus stores with the object
			// existence check enabled.
			if strings.Contains(grant.Object, "*") && (!e.SkipMissingObjects || grant.Kind != "incus") {
				slog.Warn("Skipping grant with wildcard object, this requires skip_missing_objects on an Incus store", slog.String("source", src.Name()), slog.String("object", grant.Object))

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
		objects, err := target.ExistingObjects(ctx)
		if err != nil {
			return err
		}

		filtered = map[Tuple]bool{}

		for tuple := range desired {
			// Wildcards expand to every matching object in the store.
			if strings.Contains(tuple.Object, "*") {
				for _, object := range matchObjects(objects, tuple.Object) {
					filtered[Tuple{User: tuple.User, Relation: tuple.Relation, Object: object}] = true
				}

				continue
			}

			if !objectExists(objects, tuple.Object) {
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
			if !e.managesGroup(group) {
				slog.Debug("Skipping group outside of scope", slog.String("store", target.StoreName()), slog.String("group", group))

				continue
			}

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
	// mode that's every user tuple present in the store and within our
	// scope, so anything unexpected gets deleted. Otherwise it's the
	// record of the tuples openfga-sync itself wrote, so other tuples
	// are never touched.
	current, err := target.UserTuples(ctx)
	if err != nil {
		return err
	}

	var managed map[Tuple]bool

	pruned := 0

	if e.Authoritative {
		managed = e.authoritativeScope(current)
	} else {
		managed = map[Tuple]bool{}

		// Recorded tuples that went missing from the store (e.g.
		// removed by Incus along with their object, or by hand) are
		// dropped from the record so they get re-created if still
		// wanted.
		for _, tuple := range e.State.Targets[target.StoreName()] {
			if !current[tuple] {
				slog.Info("Dropping managed tuple missing from store", slog.String("store", target.StoreName()), slog.String("tuple", tuple.String()))

				pruned++

				continue
			}

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

	if len(writes) == 0 && len(deletes) == 0 && pruned == 0 {
		return nil
	}

	appliedWrites, appliedDeletes, applyErr := target.Apply(ctx, writes, deletes)

	if !e.Authoritative {
		err := e.State.SaveTarget(target.StoreName(), computeManaged(filtered, managed, appliedWrites, deletes, appliedDeletes))
		if err != nil {
			return errors.Join(applyErr, err)
		}
	}

	if len(writes) > 0 || len(deletes) > 0 {
		slog.Info("Synchronized store", slog.String("store", target.StoreName()), slog.Int("writes", len(appliedWrites)), slog.Int("deletes", len(appliedDeletes)))
	}

	return applyErr
}

// managesGroup reports whether any resolver manages the group.
func (e *Engine) managesGroup(name string) bool {
	for _, resolver := range e.Resolvers {
		if resolver.ManagesGroup(name) {
			return true
		}
	}

	return false
}

// authoritativeScope narrows the user tuples of a store down to those
// owned in authoritative mode: group memberships are owned for the groups
// managed by the resolvers, permission tuples only when sources provide
// grants.
func (e *Engine) authoritativeScope(current map[Tuple]bool) map[Tuple]bool {
	managed := map[Tuple]bool{}

	for tuple := range current {
		group, ok := groupMembership(tuple)
		if ok {
			if e.managesGroup(group) {
				managed[tuple] = true
			}

			continue
		}

		if len(e.Sources) > 0 {
			managed[tuple] = true
		}
	}

	return managed
}

// objectExists checks whether the object referenced by a tuple exists on the
// target, using the objects found through the anchor tuples managed by Incus
// itself.
func objectExists(objects map[string]bool, object string) bool {
	objType := objectType(object)

	// The server object always exists and groups/users have no anchor
	// tuples to check for.
	if objType == "server" || objType == "group" || objType == "user" {
		return true
	}

	return objects[object]
}

// matchObjects returns the objects matching a pattern where "*" stands for
// any single path element (anything but "/"), sorted.
func matchObjects(objects map[string]bool, pattern string) []string {
	parts := strings.Split(pattern, "*")
	for i, part := range parts {
		parts[i] = regexp.QuoteMeta(part)
	}

	matcher := regexp.MustCompile("^" + strings.Join(parts, "[^/]*") + "$")

	matches := []string{}

	for object := range objects {
		if matcher.MatchString(object) {
			matches = append(matches, object)
		}
	}

	slices.Sort(matches)

	return matches
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
