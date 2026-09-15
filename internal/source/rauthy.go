package source

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/FuturFusion/openfga-sync/internal/syncer"
	"github.com/FuturFusion/openfga-sync/shared/config"
)

// Rauthy is a Rauthy data source.
//
// With sync_roles, roles are expected to carry the OpenFGA grants as JSON
// metadata, keyed by the type of application and scoped either globally
// (all deployments of that type) or to specific deployments (target
// names):
//
//	{"openfga": {
//	    "incus": {
//	        "global": [{"relation": "user", "object": "project:app-1234-stg"}],
//	        "specific": {
//	            "cluster1": [{"relation": "viewer"}]
//	        }
//	    },
//	    "operations-center": {
//	        "global": [{"relation": "viewer"}]
//	    }
//	}}
//
// Grants without an object default to the server object of their
// application kind (e.g. "server:incus"). Users holding a role get its
// grants applied.
//
// With sync_groups, the source resolves Rauthy group membership, used to
// fill in the members of OpenFGA groups that were granted access by a
// third party.
type Rauthy struct {
	name         string
	cfg          *config.RauthySource
	client       *http.Client
	groupPattern *regexp.Regexp
}

// rauthyRole is the role record returned by the Rauthy API.
type rauthyRole struct {
	ID   string          `json:"id"`
	Name string          `json:"name"`
	Meta json.RawMessage `json:"meta"`
}

// rauthyUser is the user record returned by the Rauthy API.
type rauthyUser struct {
	ID      string   `json:"id"`
	Email   string   `json:"email"`
	Enabled bool     `json:"enabled"`
	Roles   []string `json:"roles"`
	Groups  []string `json:"groups"`
}

// rauthyGroup is the group record returned by the Rauthy API.
type rauthyGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// rauthyGrant is a single grant defined in a role's metadata.
type rauthyGrant struct {
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

// rauthyApp is the per-application section of a role's metadata.
type rauthyApp struct {
	Global   []rauthyGrant            `json:"global"`
	Specific map[string][]rauthyGrant `json:"specific"`
}

// NewRauthy creates a new Rauthy source from its configuration.
func NewRauthy(name string, cfg *config.RauthySource) (*Rauthy, error) {
	groupPattern, err := compileGroupPattern(cfg.GroupPattern)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // Explicit configuration option.
	}

	if cfg.CACertificate != "" {
		content, err := os.ReadFile(cfg.CACertificate)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(content) {
			return nil, fmt.Errorf("failed to parse CA certificate %q", cfg.CACertificate)
		}

		tlsConfig.RootCAs = pool
	}

	return &Rauthy{
		name: name,
		cfg:  cfg,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
		groupPattern: groupPattern,
	}, nil
}

// Name returns the source name.
func (r *Rauthy) Name() string {
	return r.name
}

// ManagesGroup reports whether a group falls within the source's scope.
func (r *Rauthy) ManagesGroup(name string) bool {
	return matchGroup(r.groupPattern, name)
}

// Grants pulls the roles and users from Rauthy and turns the role metadata
// into OpenFGA grants for every user holding the role.
func (r *Rauthy) Grants(ctx context.Context) ([]syncer.Grant, error) {
	// Pull the roles and extract their grants.
	roles := []rauthyRole{}

	err := r.get(ctx, "/auth/v1/roles", &roles)
	if err != nil {
		return nil, err
	}

	var rolePattern *regexp.Regexp
	if r.cfg.RolePattern != "" {
		rolePattern, err = regexp.Compile(r.cfg.RolePattern)
		if err != nil {
			return nil, fmt.Errorf("invalid role pattern %q: %w", r.cfg.RolePattern, err)
		}
	}

	roleGrants := map[string][]syncer.Grant{}

	for _, role := range roles {
		if rolePattern != nil && !rolePattern.MatchString(role.Name) {
			continue
		}

		if len(role.Meta) == 0 {
			slog.Debug("Role has no metadata", slog.String("source", r.name), slog.String("role", role.Name))

			continue
		}

		grants, err := parseRoleMeta(role.Meta)
		if err != nil {
			slog.Warn("Skipping role with invalid metadata", slog.String("source", r.name), slog.String("role", role.Name), slog.Any("error", err))

			continue
		}

		if len(grants) > 0 {
			roleGrants[role.Name] = grants
		}
	}

	if len(roleGrants) == 0 {
		return nil, nil
	}

	// Pull the users and apply the grants of their roles.
	users, err := r.users(ctx)
	if err != nil {
		return nil, err
	}

	grants := []syncer.Grant{}

	for _, user := range users {
		details := rauthyUser{}

		err := r.get(ctx, "/auth/v1/users/"+url.PathEscape(user.ID), &details)
		if err != nil {
			return nil, err
		}

		if !details.Enabled || details.Email == "" {
			continue
		}

		for _, role := range details.Roles {
			for _, grant := range roleGrants[role] {
				grant.User = syncer.ObjectUser(applyTransforms(r.cfg.UserTransforms, details.Email))
				grants = append(grants, grant)
			}
		}
	}

	return grants, nil
}

// Groups returns the membership of all the Rauthy groups, as a map of
// group name to the user names of its enabled members.
func (r *Rauthy) Groups(ctx context.Context) (map[string][]string, error) {
	groups := []rauthyGroup{}

	err := r.get(ctx, "/auth/v1/groups", &groups)
	if err != nil {
		return nil, err
	}

	membership := map[string][]string{}

	for _, group := range groups {
		if !r.ManagesGroup(group.Name) {
			continue
		}

		membership[group.Name] = []string{}
	}

	if len(membership) == 0 {
		return membership, nil
	}

	users, err := r.users(ctx)
	if err != nil {
		return nil, err
	}

	for _, user := range users {
		details := rauthyUser{}

		err := r.get(ctx, "/auth/v1/users/"+url.PathEscape(user.ID), &details)
		if err != nil {
			return nil, err
		}

		if !details.Enabled || details.Email == "" {
			continue
		}

		for _, group := range details.Groups {
			_, ok := membership[group]
			if ok {
				membership[group] = append(membership[group], applyTransforms(r.cfg.UserTransforms, details.Email))
			}
		}
	}

	return membership, nil
}

// parseRoleMeta extracts the grants from a role's JSON metadata. The
// returned grants have their user left empty, to be filled in for every
// user holding the role.
func parseRoleMeta(meta json.RawMessage) ([]syncer.Grant, error) {
	wrapped := struct {
		OpenFGA map[string]rauthyApp `json:"openfga"`
	}{}

	err := json.Unmarshal(meta, &wrapped)
	if err != nil {
		return nil, fmt.Errorf("unsupported metadata format: %w", err)
	}

	grants := []syncer.Grant{}

	for kind, app := range wrapped.OpenFGA {
		for _, grant := range app.Global {
			grants = append(grants, syncer.Grant{
				Tuple: syncer.Tuple{Relation: grant.Relation, Object: grantObject(kind, grant)},
				Kind:  kind,
			})
		}

		for target, targetGrants := range app.Specific {
			for _, grant := range targetGrants {
				grants = append(grants, syncer.Grant{
					Tuple:   syncer.Tuple{Relation: grant.Relation, Object: grantObject(kind, grant)},
					Kind:    kind,
					Targets: []string{target},
				})
			}
		}
	}

	return grants, nil
}

// grantObject returns the object of a grant, defaulting to the server
// object of the application kind when unspecified.
func grantObject(kind string, grant rauthyGrant) string {
	if grant.Object == "" {
		return config.ServerObjects[kind]
	}

	return grant.Object
}

// users returns the full user list, handling server side pagination.
func (r *Rauthy) users(ctx context.Context) ([]rauthyUser, error) {
	users := []rauthyUser{}

	token := ""

	for {
		path := "/auth/v1/users"
		if token != "" {
			path += "?continuation_token=" + url.QueryEscape(token)
		}

		page := []rauthyUser{}

		header, err := r.request(ctx, path, &page)
		if err != nil {
			return nil, err
		}

		users = append(users, page...)

		token = header.Get("x-continuation-token")
		if token == "" {
			break
		}
	}

	return users, nil
}

// get performs an API request and decodes the response body.
func (r *Rauthy) get(ctx context.Context, path string, target any) error {
	_, err := r.request(ctx, path, target)

	return err
}

// request performs an API request and returns the response headers.
func (r *Rauthy) request(ctx context.Context, path string, target any) (http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(r.cfg.URL, "/")+path, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "API-Key "+r.cfg.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query %q: %w", path, err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		content, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))

		return nil, fmt.Errorf("failed to query %q: %s (%s)", path, resp.Status, strings.TrimSpace(string(content)))
	}

	err = json.NewDecoder(resp.Body).Decode(target)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response from %q: %w", path, err)
	}

	return resp.Header, nil
}
