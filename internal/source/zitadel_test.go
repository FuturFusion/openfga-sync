package source

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/FuturFusion/openfga-sync/shared/config"
)

// newZitadelServer mocks the Zitadel API, serving the given authorizations
// (paginated) and user records. The returned map counts the requests per
// path.
func newZitadelServer(t *testing.T, auths []zitadelAuthorization, users map[string]string) (*httptest.Server, map[string]int) {
	t.Helper()

	requests := map[string]int{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			http.Error(w, "bad token", http.StatusUnauthorized)

			return
		}

		requests[r.URL.Path]++

		if r.URL.Path == "/zitadel.authorization.v2.AuthorizationService/ListAuthorizations" {
			request := struct {
				Pagination struct {
					Offset int `json:"offset"`
					Limit  int `json:"limit"`
				} `json:"pagination"`
			}{}

			err := json.NewDecoder(r.Body).Decode(&request)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)

				return
			}

			page := []zitadelAuthorization{}
			for i := request.Pagination.Offset; i < len(auths) && i < request.Pagination.Offset+request.Pagination.Limit; i++ {
				page = append(page, auths[i])
			}

			err = json.NewEncoder(w).Encode(map[string]any{"authorizations": page})
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			return
		}

		userID, ok := strings.CutPrefix(r.URL.Path, "/v2/users/")
		if ok {
			record := map[string]any{"state": "USER_STATE_ACTIVE"}

			email, ok := users[userID]
			if ok {
				record["human"] = map[string]any{"email": map[string]any{"email": email}}
			}

			if userID == "inactive" {
				record["state"] = "USER_STATE_INACTIVE"
			}

			err := json.NewEncoder(w).Encode(map[string]any{"user": record})
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			return
		}

		http.NotFound(w, r)
	})

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	return server, requests
}

func TestZitadelGrants(t *testing.T) {
	t.Parallel()

	auths := []zitadelAuthorization{
		{State: "STATE_ACTIVE", User: zitadelUser{ID: "user1"}, Roles: []zitadelRole{{Key: "app-1234-admin"}}},
		{State: "STATE_ACTIVE", User: zitadelUser{ID: "user1"}, Roles: []zitadelRole{{Key: "blah-operator"}}},
		{State: "STATE_ACTIVE", User: zitadelUser{ID: "machine"}, Roles: []zitadelRole{{Key: "app-x-admin"}}},
		{State: "STATE_ACTIVE", User: zitadelUser{ID: "inactive"}, Roles: []zitadelRole{{Key: "app-x-admin"}}},
		{State: "STATE_ACTIVE", User: zitadelUser{ID: "user2"}, Roles: []zitadelRole{{Key: "unrelated"}}},
		{State: "STATE_INACTIVE", User: zitadelUser{ID: "user3"}, Roles: []zitadelRole{{Key: "app-x-admin"}}},
	}

	users := map[string]string{
		"user1":    "u1@example.com",
		"inactive": "u3@example.com",
		"user2":    "u2@example.com",
	}

	server, requests := newZitadelServer(t, auths, users)

	src, err := NewZitadel("test", &config.ZitadelSource{
		URL:       server.URL,
		APIToken:  "token",
		UserField: "email",
		Roles: []config.Role{
			{Pattern: "^app-(?P<app>.+)-admin$", Grants: []config.RoleGrant{
				{Relation: "operator", Object: "project:app-${app}-stg", Type: "incus"},
				{Relation: "viewer", Object: "project:app-${app}-prod", Type: "incus"},
			}},
			{Pattern: "^(?P<project>.+)-operator$", Grants: []config.RoleGrant{
				{Relation: "operator", Object: "project:${project}", Type: "incus", Targets: []string{"cl001"}},
			}},
		},
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	src.pageSize = 2

	grants, err := src.Grants(t.Context())
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// user1 gets 2 grants from app-1234-admin and 1 from blah-operator,
	// the machine user, the inactive user and the inactive authorization
	// are all skipped.
	if len(grants) != 3 {
		t.Fatalf("Unexpected grants: %+v", grants)
	}

	for _, grant := range grants {
		if grant.User != "user:u1@example.com" {
			t.Errorf("Unexpected grant user: %+v", grant)
		}
	}

	if grants[0].Relation != "operator" || grants[0].Object != "project:app-1234-stg" {
		t.Errorf("Unexpected grant: %+v", grants[0])
	}

	if grants[2].Object != "project:blah" || len(grants[2].Targets) != 1 || grants[2].Targets[0] != "cl001" {
		t.Errorf("Unexpected grant: %+v", grants[2])
	}

	// 6 authorizations at 2 per page, plus the final empty page.
	if requests["/zitadel.authorization.v2.AuthorizationService/ListAuthorizations"] != 4 {
		t.Errorf("Unexpected request counts: %v", requests)
	}

	// user1 is looked up once despite holding two authorizations, users
	// without matching roles or from inactive authorizations not at all.
	if requests["/v2/users/user1"] != 1 || requests["/v2/users/user2"] != 0 || requests["/v2/users/user3"] != 0 {
		t.Errorf("Unexpected request counts: %v", requests)
	}
}

func TestZitadelUserField(t *testing.T) {
	t.Parallel()

	auths := []zitadelAuthorization{
		{State: "STATE_ACTIVE", User: zitadelUser{ID: "123", PreferredLoginName: "jdoe@example.com"}, Roles: []zitadelRole{{Key: "app-1234-admin"}}},
	}

	server, requests := newZitadelServer(t, auths, nil)

	roles := []config.Role{
		{Pattern: "^app-(.+)-admin$", Grants: []config.RoleGrant{
			{Relation: "operator", Object: "project:${1}", Type: "incus"},
		}},
	}

	expected := map[string]string{
		"id":         "user:123",
		"login_name": "user:jdoe@example.com",
	}

	for field, user := range expected {
		src, err := NewZitadel("test", &config.ZitadelSource{
			URL:       server.URL,
			APIToken:  "token",
			UserField: field,
			Roles:     roles,
		})
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		grants, err := src.Grants(t.Context())
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		if len(grants) != 1 || grants[0].User != user {
			t.Errorf("Unexpected grants for %q: %+v", field, grants)
		}
	}

	// Neither field needs a user lookup.
	if requests["/v2/users/123"] != 0 {
		t.Errorf("Unexpected request counts: %v", requests)
	}
}
