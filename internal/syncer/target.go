package syncer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	openfga "github.com/openfga/go-sdk"
	"github.com/openfga/go-sdk/client"
	"github.com/openfga/go-sdk/credentials"

	"github.com/FuturFusion/openfga-sync/shared/config"
)

// Instance wraps the OpenFGA instance hosting the stores to synchronize.
type Instance struct {
	cfg *config.OpenFGA
}

// Target wraps a single OpenFGA store to synchronize.
type Target struct {
	name      string
	kind      string
	storeName string
	client    *client.OpenFgaClient

	// tuples caches the full content of the store for the pass.
	tuples []Tuple
}

// NewInstance creates a new OpenFGA instance wrapper from its configuration.
func NewInstance(cfg *config.OpenFGA) *Instance {
	return &Instance{
		cfg: cfg,
	}
}

// Targets discovers the stores present on the instance, following the
// "TYPE_NAME" store naming convention. Stores that don't match the
// convention are ignored.
func (i *Instance) Targets(ctx context.Context) ([]*Target, error) {
	fga, err := i.newClient("")
	if err != nil {
		return nil, err
	}

	targets := []*Target{}

	token := ""

	for {
		opts := client.ClientListStoresOptions{
			ContinuationToken: openfga.PtrString(token),
		}

		resp, err := fga.ListStores(ctx).Options(opts).Execute()
		if err != nil {
			return nil, fmt.Errorf("failed to list the stores: %w", err)
		}

		for _, store := range resp.Stores {
			kind, name, ok := strings.Cut(store.Name, "_")
			if !ok || name == "" || !slices.Contains(config.ApplicationKinds, kind) {
				slog.Debug("Ignoring store not following the naming convention", slog.String("store", store.Name))

				continue
			}

			storeClient, err := i.newClient(store.Id)
			if err != nil {
				return nil, err
			}

			targets = append(targets, &Target{
				name:      name,
				kind:      kind,
				storeName: store.Name,
				client:    storeClient,
			})
		}

		token = resp.ContinuationToken
		if token == "" {
			break
		}
	}

	return targets, nil
}

// newClient creates an OpenFGA API client for the given store.
func (i *Instance) newClient(storeID string) (*client.OpenFgaClient, error) {
	conf := client.ClientConfiguration{
		ApiUrl:  i.cfg.URL,
		StoreId: storeID,
	}

	if i.cfg.InsecureSkipVerify {
		conf.HTTPClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec // Explicit configuration option.
				},
			},
		}
	}

	if i.cfg.APIToken != "" {
		conf.Credentials = &credentials.Credentials{
			Method: credentials.CredentialsMethodApiToken,
			Config: &credentials.Config{
				ApiToken: i.cfg.APIToken,
			},
		}
	}

	fga, err := client.NewSdkClient(&conf)
	if err != nil {
		return nil, fmt.Errorf("failed to create the OpenFGA client: %w", err)
	}

	return fga, nil
}

// Name returns the deployment name of the target (the part of the store
// name after the application type).
func (t *Target) Name() string {
	return t.name
}

// Kind returns the type of application using the store.
func (t *Target) Kind() string {
	return t.kind
}

// StoreName returns the full store name (used as the state file key).
func (t *Target) StoreName() string {
	return t.storeName
}

// ExistingObjects returns the objects present in the store, based on the
// anchor tuples maintained by Incus: every object it manages is linked to
// its parent through a "project" or "server" relation tuple.
func (t *Target) ExistingObjects(ctx context.Context) (map[string]bool, error) {
	tuples, err := t.allTuples(ctx)
	if err != nil {
		return nil, err
	}

	objects := map[string]bool{}

	for _, tuple := range tuples {
		if tuple.Relation == "project" || tuple.Relation == "server" {
			objects[tuple.Object] = true
		}
	}

	return objects, nil
}

// ReferencedGroups returns the names of the groups referenced as the user
// of permission tuples in the store (the "group:NAME#member" form).
func (t *Target) ReferencedGroups(ctx context.Context) ([]string, error) {
	tuples, err := t.allTuples(ctx)
	if err != nil {
		return nil, err
	}

	groups := []string{}

	for _, tuple := range tuples {
		name, ok := groupReference(tuple.User)
		if ok && !slices.Contains(groups, name) {
			groups = append(groups, name)
		}
	}

	return groups, nil
}

// UserTuples returns all the user permission tuples present in the store,
// excluding the "user:*" wildcard used for authenticated access. Tuples
// granted to groups (group:NAME#member) are left out as those can be
// managed by a third party.
func (t *Target) UserTuples(ctx context.Context) (map[Tuple]bool, error) {
	tuples, err := t.allTuples(ctx)
	if err != nil {
		return nil, err
	}

	current := map[Tuple]bool{}

	for _, tuple := range tuples {
		if strings.HasPrefix(tuple.User, "user:") && tuple.User != "user:*" {
			current[tuple] = true
		}
	}

	return current, nil
}

// writeChunkSize is the maximum number of changes per OpenFGA write request.
const writeChunkSize = 100

// Apply sends the writes and deletes to the store and returns the tuples
// which were successfully applied. Writing a tuple which already exists and
// deleting a tuple which doesn't are both treated as success, making the
// operation idempotent.
func (t *Target) Apply(ctx context.Context, writes []Tuple, deletes []Tuple) ([]Tuple, []Tuple, error) {
	errs := []error{}
	appliedWrites := []Tuple{}
	appliedDeletes := []Tuple{}

	for chunk := range slices.Chunk(writes, writeChunkSize) {
		applied, chunkErrs := t.applyChunk(ctx, chunk, false)
		appliedWrites = append(appliedWrites, applied...)
		errs = append(errs, chunkErrs...)
	}

	for chunk := range slices.Chunk(deletes, writeChunkSize) {
		applied, chunkErrs := t.applyChunk(ctx, chunk, true)
		appliedDeletes = append(appliedDeletes, applied...)
		errs = append(errs, chunkErrs...)
	}

	if len(writes) > 0 || len(deletes) > 0 {
		slog.Debug("Applied tuple changes", slog.String("store", t.storeName), slog.Int("writes", len(appliedWrites)), slog.Int("deletes", len(appliedDeletes)))
	}

	return appliedWrites, appliedDeletes, errors.Join(errs...)
}

// applyChunk sends a batch of changes in a single transactional request.
// On failure, the chunk is split into individual requests so that tuples
// which are already in the wanted state don't fail the others.
func (t *Target) applyChunk(ctx context.Context, tuples []Tuple, deletion bool) ([]Tuple, []error) {
	body := client.ClientWriteRequest{
		Writes:  []client.ClientTupleKey{},
		Deletes: []openfga.TupleKeyWithoutCondition{},
	}

	for _, tuple := range tuples {
		if deletion {
			body.Deletes = append(body.Deletes, openfga.TupleKeyWithoutCondition{
				User:     tuple.User,
				Relation: tuple.Relation,
				Object:   tuple.Object,
			})
		} else {
			body.Writes = append(body.Writes, client.ClientTupleKey{
				User:     tuple.User,
				Relation: tuple.Relation,
				Object:   tuple.Object,
			})
		}
	}

	_, err := t.client.Write(ctx).Body(body).Execute()
	if err == nil {
		return tuples, nil
	}

	if len(tuples) == 1 {
		// A tuple already in the wanted state counts as applied.
		if !deletion && strings.Contains(err.Error(), "already exists") {
			return tuples, nil
		}

		if deletion && strings.Contains(err.Error(), "does not exist") {
			return tuples, nil
		}

		op := "write"
		if deletion {
			op = "delete"
		}

		return nil, []error{fmt.Errorf("failed to %s tuple %s on store %q: %w", op, tuples[0], t.storeName, err)}
	}

	// Isolate the offending tuples.
	applied := []Tuple{}
	errs := []error{}

	for _, tuple := range tuples {
		tupleApplied, tupleErrs := t.applyChunk(ctx, []Tuple{tuple}, deletion)
		applied = append(applied, tupleApplied...)
		errs = append(errs, tupleErrs...)
	}

	return applied, errs
}

// allTuples returns every tuple of the store, read once per pass.
func (t *Target) allTuples(ctx context.Context) ([]Tuple, error) {
	if t.tuples != nil {
		return t.tuples, nil
	}

	tuples, err := t.read(ctx, client.ClientReadRequest{})
	if err != nil {
		return nil, err
	}

	slog.Debug("Read store tuples", slog.String("store", t.storeName), slog.Int("count", len(tuples)))

	t.tuples = tuples

	return tuples, nil
}

// read runs a single paginated Read query and returns the matching tuples.
func (t *Target) read(ctx context.Context, body client.ClientReadRequest) ([]Tuple, error) {
	tuples := []Tuple{}

	token := ""

	for {
		opts := client.ClientReadOptions{
			PageSize:          openfga.PtrInt32(100),
			ContinuationToken: openfga.PtrString(token),
		}

		resp, err := t.client.Read(ctx).Body(body).Options(opts).Execute()
		if err != nil {
			return nil, fmt.Errorf("failed to read tuples from store %q: %w", t.storeName, err)
		}

		for _, tuple := range resp.Tuples {
			tuples = append(tuples, Tuple{
				User:     tuple.Key.User,
				Relation: tuple.Key.Relation,
				Object:   tuple.Key.Object,
			})
		}

		token = resp.ContinuationToken
		if token == "" {
			break
		}
	}

	return tuples, nil
}
