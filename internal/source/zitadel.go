package source

import (
	"bytes"
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
	"strings"

	"github.com/FuturFusion/openfga-sync/internal/syncer"
	"github.com/FuturFusion/openfga-sync/shared/config"
)

// zitadelPageSize is the number of authorizations requested per page. It
// matches the Zitadel default limit, staying below the runtime maximum.
const zitadelPageSize = 100

// Zitadel is a Zitadel data source.
//
// Project role assignments (authorizations) are pulled through the v2
// authorization API and the role keys matched against the configured role
// patterns, applying their grants to every user holding the role. Zitadel
// roles can't carry metadata, so the grants live in the configuration,
// mirroring the LDAP source.
type Zitadel struct {
	name     string
	cfg      *config.ZitadelSource
	client   *http.Client
	pageSize int
}

// zitadelAuthorization is an authorization returned by the Zitadel API.
type zitadelAuthorization struct {
	State string        `json:"state"`
	User  zitadelUser   `json:"user"`
	Roles []zitadelRole `json:"roles"`
}

// zitadelUser is the user summary embedded in an authorization.
type zitadelUser struct {
	ID                 string `json:"id"`
	PreferredLoginName string `json:"preferredLoginName"` //nolint:tagliatelle // Zitadel uses camelCase.
}

// zitadelRole is a role granted through an authorization.
type zitadelRole struct {
	Key string `json:"key"`
}

// zitadelUserDetails is the record returned by the user API, reduced to the
// fields needed to resolve the e-mail address.
type zitadelUserDetails struct {
	User struct {
		State string `json:"state"`
		Human *struct {
			Email struct {
				Email string `json:"email"`
			} `json:"email"`
		} `json:"human"`
	} `json:"user"`
}

// NewZitadel creates a new Zitadel source from its configuration.
func NewZitadel(name string, cfg *config.ZitadelSource) (*Zitadel, error) {
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

	return &Zitadel{
		name: name,
		cfg:  cfg,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
		pageSize: zitadelPageSize,
	}, nil
}

// Name returns the source name.
func (z *Zitadel) Name() string {
	return z.name
}

// Grants pulls the active role assignments from Zitadel and turns the role
// keys into OpenFGA grants through the configured roles.
func (z *Zitadel) Grants(ctx context.Context) ([]syncer.Grant, error) {
	roles, err := compileRoles(z.cfg.Roles)
	if err != nil {
		return nil, err
	}

	auths, err := z.authorizations(ctx)
	if err != nil {
		return nil, err
	}

	grants := []syncer.Grant{}
	userCache := map[string]string{}

	for _, auth := range auths {
		if auth.State != "STATE_ACTIVE" {
			continue
		}

		for _, role := range auth.Roles {
			roleGrants := mapName(roles, role.Key)
			if len(roleGrants) == 0 {
				slog.Debug("Role doesn't match any pattern", slog.String("source", z.name), slog.String("role", role.Key))

				continue
			}

			userName, err := z.userName(ctx, auth.User, userCache)
			if err != nil {
				return nil, err
			}

			if userName == "" {
				slog.Warn("Skipping unresolvable user", slog.String("source", z.name), slog.String("user", auth.User.ID))

				continue
			}

			for _, grant := range roleGrants {
				grant.User = syncer.ObjectUser(userName)
				grants = append(grants, grant)
			}
		}
	}

	return grants, nil
}

// authorizations returns all the active authorizations, handling pagination.
func (z *Zitadel) authorizations(ctx context.Context) ([]zitadelAuthorization, error) {
	filters := []map[string]any{
		{"state": map[string]any{"state": "STATE_ACTIVE"}},
	}

	if z.cfg.ProjectID != "" {
		filters = append(filters, map[string]any{"projectId": map[string]any{"id": z.cfg.ProjectID}})
	}

	auths := []zitadelAuthorization{}

	for offset := 0; ; offset += z.pageSize {
		request := map[string]any{
			"pagination": map[string]any{
				"offset": offset,
				"limit":  z.pageSize,
				"asc":    true,
			},
			"sortingColumn": "AUTHORIZATION_FIELD_NAME_CREATED_DATE",
			"filters":       filters,
		}

		response := struct {
			Authorizations []zitadelAuthorization `json:"authorizations"`
		}{}

		err := z.post(ctx, "/zitadel.authorization.v2.AuthorizationService/ListAuthorizations", request, &response)
		if err != nil {
			return nil, err
		}

		auths = append(auths, response.Authorizations...)

		if len(response.Authorizations) < z.pageSize {
			return auths, nil
		}
	}
}

// userName resolves an authorization's user to the OpenFGA user name,
// according to the configured user field.
func (z *Zitadel) userName(ctx context.Context, user zitadelUser, cache map[string]string) (string, error) {
	switch z.cfg.UserField {
	case "id":
		return user.ID, nil

	case "login_name":
		return user.PreferredLoginName, nil
	}

	// The e-mail address needs a lookup of the full user record.
	email, ok := cache[user.ID]
	if ok {
		return email, nil
	}

	details := zitadelUserDetails{}

	err := z.get(ctx, "/v2/users/"+url.PathEscape(user.ID), &details)
	if err != nil {
		return "", err
	}

	// Machine users have no e-mail address and inactive users shouldn't
	// be granted anything.
	if details.User.Human == nil || details.User.State != "USER_STATE_ACTIVE" {
		cache[user.ID] = ""

		return "", nil
	}

	cache[user.ID] = details.User.Human.Email.Email

	return cache[user.ID], nil
}

// get performs a GET API request and decodes the response body.
func (z *Zitadel) get(ctx context.Context, path string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(z.cfg.URL, "/")+path, nil)
	if err != nil {
		return err
	}

	return z.do(req, path, target)
}

// post performs a POST API request with a JSON body and decodes the
// response body.
func (z *Zitadel) post(ctx context.Context, path string, body any, target any) error {
	content, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(z.cfg.URL, "/")+path, bytes.NewReader(content))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connect-Protocol-Version", "1")

	return z.do(req, path, target)
}

// do performs an API request and decodes the response body.
func (z *Zitadel) do(req *http.Request, path string, target any) error {
	req.Header.Set("Authorization", "Bearer "+z.cfg.APIToken)
	req.Header.Set("Accept", "application/json")

	resp, err := z.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to query %q: %w", path, err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		content, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))

		return fmt.Errorf("failed to query %q: %s (%s)", path, resp.Status, strings.TrimSpace(string(content)))
	}

	err = json.NewDecoder(resp.Body).Decode(target)
	if err != nil {
		return fmt.Errorf("failed to parse response from %q: %w", path, err)
	}

	return nil
}
