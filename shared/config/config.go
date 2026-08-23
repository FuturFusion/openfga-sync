// Package config handles the openfga-sync configuration file.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"time"

	"go.yaml.in/yaml/v4"
)

// Duration wraps time.Duration to allow parsing from YAML and JSON strings
// like "15m".
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler for Duration.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string

	err := value.Decode(&s)
	if err != nil {
		return err
	}

	return d.parse(s)
}

// MarshalYAML implements yaml.Marshaler for Duration.
func (d Duration) MarshalYAML() (any, error) {
	return time.Duration(d).String(), nil
}

// UnmarshalJSON implements json.Unmarshaler for Duration.
func (d *Duration) UnmarshalJSON(data []byte) error {
	var s string

	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}

	return d.parse(s)
}

// MarshalJSON implements json.Marshaler for Duration.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) parse(s string) error {
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}

	*d = Duration(parsed)

	return nil
}

// Config is the top-level configuration for openfga-sync.
type Config struct {
	Daemon  Daemon   `json:"daemon"  yaml:"daemon"`
	Sources []Source `json:"sources" yaml:"sources"`
	OpenFGA OpenFGA  `json:"openfga" yaml:"openfga"`
}

// Daemon holds the daemon-level settings.
type Daemon struct {
	// Interval between two synchronization runs.
	Interval Duration `json:"interval" yaml:"interval"`

	// StateDir is where the record of managed tuples is kept, one file
	// per store.
	StateDir string `json:"state_dir" yaml:"state_dir"`
}

// Source is the configuration of a single data source.
type Source struct {
	Name    string         `json:"name"              yaml:"name"`
	Type    string         `json:"type"              yaml:"type"`
	LDAP    *LDAPSource    `json:"ldap,omitempty"    yaml:"ldap,omitempty"`
	Rauthy  *RauthySource  `json:"rauthy,omitempty"  yaml:"rauthy,omitempty"`
	Zitadel *ZitadelSource `json:"zitadel,omitempty" yaml:"zitadel,omitempty"`
}

// LDAPSource is the configuration of an AD/LDAP data source.
type LDAPSource struct {
	// URL of the server (ldap://, ldaps://). When empty, the servers
	// are discovered through the AD DNS SRV records of Domain.
	URL string `json:"url" yaml:"url"`

	// Domain is the AD DNS domain used to discover the LDAP servers
	// when no URL is set.
	Domain string `json:"domain" yaml:"domain"`

	// StartTLS upgrades a plain-text connection to TLS after connecting.
	StartTLS bool `json:"start_tls" yaml:"start_tls"`

	// InsecureSkipVerify disables the server certificate validation.
	InsecureSkipVerify bool `json:"insecure_skip_verify" yaml:"insecure_skip_verify"`

	// CACertificate is the path to a PEM file used to validate the server certificate.
	CACertificate string `json:"ca_certificate" yaml:"ca_certificate"`

	// BindDN and BindPassword are used for the initial bind (empty for anonymous).
	BindDN       string `json:"bind_dn"       yaml:"bind_dn"`
	BindPassword string `json:"bind_password" yaml:"bind_password"`

	// GroupBaseDN is the DN under which all relevant groups are located.
	GroupBaseDN string `json:"group_base_dn" yaml:"group_base_dn"`

	// GroupFilter is the LDAP filter used to select the groups.
	GroupFilter string `json:"group_filter" yaml:"group_filter"`

	// GroupNameAttribute is the attribute holding the group name.
	GroupNameAttribute string `json:"group_name_attribute" yaml:"group_name_attribute"`

	// MemberAttribute is the group attribute holding its members.
	MemberAttribute string `json:"member_attribute" yaml:"member_attribute"`

	// UserAttribute is the user attribute used as the OpenFGA user name.
	// When set, each member DN is resolved to this attribute through an
	// extra query per user. If empty, the user name is derived from the
	// member value itself: the first RDN value for DNs (for AD, the CN
	// is expected to line up with the sAMAccountName), the raw value
	// otherwise (e.g. memberUid on posixGroup).
	UserAttribute string `json:"user_attribute" yaml:"user_attribute"`

	// SyncRoles applies the grants of the roles below to the members of
	// the matching groups.
	SyncRoles bool `json:"sync_roles" yaml:"sync_roles"`

	// SyncGroups synchronizes the membership of the OpenFGA groups that
	// were granted access in the stores by a third party, filling in the
	// "member" tuples from the matching LDAP groups. This requires
	// reading all the tuples of every store on each pass.
	SyncGroups bool `json:"sync_groups" yaml:"sync_groups"`

	// Roles translate group names into sets of OpenFGA grants.
	Roles []Role `json:"roles" yaml:"roles"`
}

// Role maps a name pattern (LDAP group name, Zitadel role key) to a set of
// OpenFGA grants, applied to every user holding the matching roles.
type Role struct {
	// Pattern is a regular expression matched against the name.
	Pattern string `json:"pattern" yaml:"pattern"`

	// Grants are the grants held by the role.
	Grants []RoleGrant `json:"grants" yaml:"grants"`
}

// RoleGrant is a single grant defined by a role.
type RoleGrant struct {
	// Relation is the OpenFGA relation to grant. Capture groups from
	// the role pattern can be referenced as ${1} or ${name}.
	Relation string `json:"relation" yaml:"relation"`

	// Object is the OpenFGA object template. Capture groups from the
	// role pattern can be referenced as ${1} or ${name}.
	// Defaults to "project:${1}" for the "incus" type and to the
	// application's server object for the other types.
	Object string `json:"object" yaml:"object"`

	// Type is the type of application the grant applies to ("incus",
	// "operations-center" or "migration-manager"). Defaults to "incus".
	Type string `json:"type" yaml:"type"`

	// Targets restricts the grant to specific deployments (target
	// names). When empty, the grant applies to all deployments of the
	// application type.
	Targets []string `json:"targets" yaml:"targets"`
}

// RauthySource is the configuration of a Rauthy data source.
type RauthySource struct {
	// URL of the Rauthy server.
	URL string `json:"url" yaml:"url"`

	// APIKey is the Rauthy API key (needs read access to roles, users
	// and groups).
	APIKey string `json:"api_key" yaml:"api_key"`

	// InsecureSkipVerify disables the server certificate validation.
	InsecureSkipVerify bool `json:"insecure_skip_verify" yaml:"insecure_skip_verify"`

	// CACertificate is the path to a PEM file used to validate the server certificate.
	CACertificate string `json:"ca_certificate" yaml:"ca_certificate"`

	// RolePattern is a regular expression used to select the relevant roles.
	RolePattern string `json:"role_pattern" yaml:"role_pattern"`

	// SyncRoles pulls the roles matching RolePattern and applies the
	// OpenFGA grants defined in their metadata to every user holding
	// them.
	SyncRoles bool `json:"sync_roles" yaml:"sync_roles"`

	// SyncGroups synchronizes the membership of the OpenFGA groups that
	// were granted access in the stores by a third party, filling in the
	// "member" tuples from the matching Rauthy groups. This requires
	// reading all the tuples of every store on each pass.
	SyncGroups bool `json:"sync_groups" yaml:"sync_groups"`
}

// ZitadelSource is the configuration of a Zitadel data source.
type ZitadelSource struct {
	// URL of the Zitadel instance.
	URL string `json:"url" yaml:"url"`

	// APIToken is the personal access token of a Zitadel service user
	// with permission to read authorizations (user.grant.read).
	APIToken string `json:"api_token" yaml:"api_token"`

	// InsecureSkipVerify disables the server certificate validation.
	InsecureSkipVerify bool `json:"insecure_skip_verify" yaml:"insecure_skip_verify"`

	// CACertificate is the path to a PEM file used to validate the server certificate.
	CACertificate string `json:"ca_certificate" yaml:"ca_certificate"`

	// ProjectID restricts the synchronization to the role assignments of
	// a single Zitadel project. When empty, all projects are considered.
	ProjectID string `json:"project_id" yaml:"project_id"`

	// UserField selects the value used as the OpenFGA user name:
	// "email" (the default, needs one extra query per user),
	// "login_name" (the preferred login name) or "id" (the user ID,
	// matching the OIDC subject).
	UserField string `json:"user_field" yaml:"user_field"`

	// SyncRoles applies the grants of the roles below to the users
	// holding the matching Zitadel roles.
	SyncRoles bool `json:"sync_roles" yaml:"sync_roles"`

	// Roles translate Zitadel role keys into sets of OpenFGA grants.
	Roles []Role `json:"roles" yaml:"roles"`
}

// ApplicationKinds are the types of applications a target can be.
var ApplicationKinds = []string{"incus", "operations-center", "migration-manager"}

// ServerObjects maps an application kind to its server object, used as the
// default object for grants which don't specify one.
var ServerObjects = map[string]string{
	"incus":             "server:incus",
	"operations-center": "server:operations-center",
	"migration-manager": "server:migration-manager",
}

// OpenFGA is the configuration of the OpenFGA instance to synchronize.
//
// The stores hosted on the instance are discovered automatically, based on
// the "TYPE_NAME" store naming convention (e.g. "incus_cl001" for the Incus
// deployment named "cl001").
type OpenFGA struct {
	// URL of the OpenFGA API.
	URL string `json:"url" yaml:"url"`

	// APIToken is the pre-shared OpenFGA API token.
	APIToken string `json:"api_token" yaml:"api_token"`

	// InsecureSkipVerify disables the server certificate validation.
	InsecureSkipVerify bool `json:"insecure_skip_verify" yaml:"insecure_skip_verify"`

	// Authoritative makes openfga-sync the owner of all user permission
	// tuples in the stores. Instead of only ever deleting the tuples it
	// created itself (tracked in the state directory), it compares the
	// desired grants with all the user tuples present in each store and
	// deletes anything unexpected. The state directory is unused in
	// this mode.
	Authoritative bool `json:"authoritative" yaml:"authoritative"`

	// SkipMissingObjects only pushes tuples whose objects exist in the
	// store (based on the object tuples maintained by Incus), skipping
	// the others until a later pass where the objects showed up.
	SkipMissingObjects bool `json:"skip_missing_objects" yaml:"skip_missing_objects"`
}

// Load reads, parses and validates the configuration file.
func Load(path string) (*Config, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration: %w", err)
	}

	cfg := &Config{}

	err = yaml.Unmarshal(content, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse configuration: %w", err)
	}

	err = cfg.Validate()
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate checks the configuration and applies the defaults.
func (c *Config) Validate() error {
	// Apply the daemon defaults.
	if c.Daemon.Interval <= 0 {
		c.Daemon.Interval = Duration(15 * time.Minute)
	}

	if c.Daemon.StateDir == "" {
		c.Daemon.StateDir = "/var/lib/openfga-sync"
	}

	// Validate the sources.
	if len(c.Sources) == 0 {
		return errors.New("at least one source must be configured")
	}

	sourceNames := map[string]bool{}

	for i := range c.Sources {
		src := &c.Sources[i]

		if src.Name == "" {
			return errors.New("sources must have a name")
		}

		if sourceNames[src.Name] {
			return fmt.Errorf("duplicate source name %q", src.Name)
		}

		sourceNames[src.Name] = true

		switch src.Type {
		case "ldap":
			if src.LDAP == nil {
				return fmt.Errorf("source %q is missing its \"ldap\" section", src.Name)
			}

			err := src.LDAP.validate(src.Name)
			if err != nil {
				return err
			}

		case "rauthy":
			if src.Rauthy == nil {
				return fmt.Errorf("source %q is missing its \"rauthy\" section", src.Name)
			}

			err := src.Rauthy.validate(src.Name)
			if err != nil {
				return err
			}

		case "zitadel":
			if src.Zitadel == nil {
				return fmt.Errorf("source %q is missing its \"zitadel\" section", src.Name)
			}

			err := src.Zitadel.validate(src.Name)
			if err != nil {
				return err
			}

		default:
			return fmt.Errorf("source %q has unsupported type %q", src.Name, src.Type)
		}
	}

	// Validate the OpenFGA instance.
	if c.OpenFGA.URL == "" {
		return errors.New("the OpenFGA URL must be configured")
	}

	return nil
}

func (l *LDAPSource) validate(name string) error {
	if l.URL == "" && l.Domain == "" {
		return fmt.Errorf("source %q needs either a URL or a domain", name)
	}

	if l.URL != "" && l.Domain != "" {
		return fmt.Errorf("source %q can't have both a URL and a domain", name)
	}

	if l.GroupBaseDN == "" {
		return fmt.Errorf("source %q is missing its group base DN", name)
	}

	// Apply the defaults.
	if l.GroupFilter == "" {
		l.GroupFilter = "(objectClass=group)"
	}

	if l.GroupNameAttribute == "" {
		l.GroupNameAttribute = "cn"
	}

	if l.MemberAttribute == "" {
		l.MemberAttribute = "member"
	}

	if !l.SyncRoles && !l.SyncGroups {
		return fmt.Errorf("source %q must enable at least one of sync_roles and sync_groups", name)
	}

	if l.SyncRoles && len(l.Roles) == 0 {
		return fmt.Errorf("source %q has no roles", name)
	}

	return validateRoles(name, l.Roles)
}

// validateRoles checks a role list and applies the grant defaults.
func validateRoles(name string, roles []Role) error {
	for i := range roles {
		role := &roles[i]

		if role.Pattern == "" {
			return fmt.Errorf("source %q has a role without a pattern", name)
		}

		_, err := regexp.Compile(role.Pattern)
		if err != nil {
			return fmt.Errorf("source %q has an invalid pattern %q: %w", name, role.Pattern, err)
		}

		if len(role.Grants) == 0 {
			return fmt.Errorf("source %q has a role without grants", name)
		}

		for j := range role.Grants {
			grant := &role.Grants[j]

			if grant.Relation == "" {
				return fmt.Errorf("source %q has a grant without a relation", name)
			}

			if grant.Type == "" {
				grant.Type = "incus"
			}

			if !slices.Contains(ApplicationKinds, grant.Type) {
				return fmt.Errorf("source %q has a grant with unsupported type %q", name, grant.Type)
			}

			if grant.Object == "" {
				if grant.Type == "incus" {
					grant.Object = "project:${1}"
				} else {
					grant.Object = ServerObjects[grant.Type]
				}
			}
		}
	}

	return nil
}

func (r *RauthySource) validate(name string) error {
	if r.URL == "" {
		return fmt.Errorf("source %q is missing its URL", name)
	}

	if r.APIKey == "" {
		return fmt.Errorf("source %q is missing its API key", name)
	}

	if r.RolePattern != "" {
		_, err := regexp.Compile(r.RolePattern)
		if err != nil {
			return fmt.Errorf("source %q has an invalid role pattern %q: %w", name, r.RolePattern, err)
		}
	}

	if !r.SyncRoles && !r.SyncGroups {
		return fmt.Errorf("source %q must enable at least one of sync_roles and sync_groups", name)
	}

	return nil
}

func (z *ZitadelSource) validate(name string) error {
	if z.URL == "" {
		return fmt.Errorf("source %q is missing its URL", name)
	}

	if z.APIToken == "" {
		return fmt.Errorf("source %q is missing its API token", name)
	}

	if z.UserField == "" {
		z.UserField = "email"
	}

	if !slices.Contains([]string{"email", "login_name", "id"}, z.UserField) {
		return fmt.Errorf("source %q has unsupported user field %q", name, z.UserField)
	}

	if !z.SyncRoles {
		return fmt.Errorf("source %q must enable sync_roles", name)
	}

	if len(z.Roles) == 0 {
		return fmt.Errorf("source %q has no roles", name)
	}

	return validateRoles(name, z.Roles)
}
