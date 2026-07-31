// Package source implements the identity data sources.
package source

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/FuturFusion/openfga-sync/internal/syncer"
	"github.com/FuturFusion/openfga-sync/shared/config"
)

// LDAP is an AD/LDAP data source.
type LDAP struct {
	name string
	cfg  *config.LDAPSource
}

// NewLDAP creates a new LDAP source from its configuration.
func NewLDAP(name string, cfg *config.LDAPSource) *LDAP {
	return &LDAP{
		name: name,
		cfg:  cfg,
	}
}

// Name returns the source name.
func (l *LDAP) Name() string {
	return l.name
}

// ldapRole is a compiled role definition.
type ldapRole struct {
	pattern *regexp.Regexp
	grants  []config.LDAPGrant
}

// ldapGroup is a group with its resolved member names.
type ldapGroup struct {
	name    string
	members []string
}

// compileRoles compiles the configured role patterns.
func compileRoles(cfgs []config.LDAPRole) ([]ldapRole, error) {
	roles := make([]ldapRole, 0, len(cfgs))
	for _, role := range cfgs {
		pattern, err := regexp.Compile(role.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid pattern %q: %w", role.Pattern, err)
		}

		roles = append(roles, ldapRole{pattern: pattern, grants: role.Grants})
	}

	return roles, nil
}

// mapGroup returns the grants of the roles matching a group name, with the
// user left empty. Capture groups from the role pattern can be referenced
// in both the relation and the object templates.
func mapGroup(roles []ldapRole, groupName string) []syncer.Grant {
	grants := []syncer.Grant{}

	for _, role := range roles {
		match := role.pattern.FindStringSubmatchIndex(groupName)
		if match == nil {
			continue
		}

		for _, grant := range role.grants {
			grants = append(grants, syncer.Grant{
				Tuple: syncer.Tuple{
					Relation: string(role.pattern.ExpandString(nil, grant.Relation, groupName, match)),
					Object:   string(role.pattern.ExpandString(nil, grant.Object, groupName, match)),
				},
				Kind:    grant.Type,
				Targets: grant.Targets,
			})
		}
	}

	return grants
}

// Grants pulls the groups below the configured base DN and turns their
// membership into OpenFGA grants through the configured roles.
func (l *LDAP) Grants(ctx context.Context) ([]syncer.Grant, error) {
	roles, err := compileRoles(l.cfg.Roles)
	if err != nil {
		return nil, err
	}

	roleGrants := map[string][]syncer.Grant{}

	groups, err := l.fetchGroups(ctx, func(groupName string) bool {
		grants := mapGroup(roles, groupName)
		if len(grants) == 0 {
			slog.Debug("Group doesn't match any role", slog.String("source", l.name), slog.String("group", groupName))

			return false
		}

		roleGrants[groupName] = grants

		return true
	})
	if err != nil {
		return nil, err
	}

	allGrants := []syncer.Grant{}

	for _, group := range groups {
		for _, userName := range group.members {
			for _, g := range roleGrants[group.name] {
				g.User = syncer.ObjectUser(userName)
				allGrants = append(allGrants, g)
			}
		}
	}

	return allGrants, nil
}

// Groups returns the membership of all the groups below the configured
// base DN, as a map of group name to the user names of its members.
func (l *LDAP) Groups(ctx context.Context) (map[string][]string, error) {
	groups, err := l.fetchGroups(ctx, nil)
	if err != nil {
		return nil, err
	}

	membership := map[string][]string{}
	for _, group := range groups {
		membership[group.name] = group.members
	}

	return membership, nil
}

// fetchGroups pulls the groups below the configured base DN and resolves their
// members. When a filter is given, groups it rejects are skipped without
// resolving their members.
func (l *LDAP) fetchGroups(ctx context.Context, filter func(string) bool) ([]ldapGroup, error) {
	conn, err := l.connect(ctx)
	if err != nil {
		return nil, err
	}

	defer conn.Close()

	// Pull all the groups.
	req := ldap.NewSearchRequest(
		l.cfg.GroupBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		l.cfg.GroupFilter,
		[]string{l.cfg.GroupNameAttribute, l.cfg.MemberAttribute},
		nil,
	)

	result, err := conn.SearchWithPaging(req, 1000)
	if err != nil {
		return nil, fmt.Errorf("failed to search for groups: %w", err)
	}

	groups := []ldapGroup{}
	userCache := map[string]string{}

	for _, entry := range result.Entries {
		err := ctx.Err()
		if err != nil {
			return nil, err
		}

		groupName := entry.GetAttributeValue(l.cfg.GroupNameAttribute)
		if groupName == "" {
			continue
		}

		if filter != nil && !filter(groupName) {
			continue
		}

		// Resolve the members.
		members, err := l.members(conn, entry.DN, entry.Attributes)
		if err != nil {
			return nil, err
		}

		group := ldapGroup{name: groupName, members: []string{}}

		for _, member := range members {
			userName, err := l.resolveMember(conn, member, userCache)
			if err != nil {
				return nil, err
			}

			if userName == "" {
				slog.Warn("Skipping unresolvable group member", slog.String("source", l.name), slog.String("group", groupName), slog.String("member", member))

				continue
			}

			group.members = append(group.members, userName)
		}

		groups = append(groups, group)
	}

	return groups, nil
}

// connect establishes the LDAP connection and performs the initial bind,
// discovering the servers through DNS when no URL is configured.
func (l *LDAP) connect(ctx context.Context) (*ldap.Conn, error) {
	urls := []string{l.cfg.URL}

	if l.cfg.URL == "" {
		var err error

		urls, err = l.discover(ctx)
		if err != nil {
			return nil, err
		}
	}

	errs := []error{}

	for _, serverURL := range urls {
		conn, err := l.connectURL(serverURL)
		if err != nil {
			errs = append(errs, err)

			continue
		}

		return conn, nil
	}

	return nil, errors.Join(errs...)
}

// discover returns the LDAP server URLs of the domain, using the DNS SRV
// records published by AD.
func (l *LDAP) discover(ctx context.Context) ([]string, error) {
	// Prefer the AD specific record as it only lists domain controllers.
	_, addrs, err := net.DefaultResolver.LookupSRV(ctx, "ldap", "tcp", "dc._msdcs."+l.cfg.Domain)
	if err != nil || len(addrs) == 0 {
		_, addrs, err = net.DefaultResolver.LookupSRV(ctx, "ldap", "tcp", l.cfg.Domain)
		if err != nil {
			return nil, fmt.Errorf("failed to discover the LDAP servers of %q: %w", l.cfg.Domain, err)
		}
	}

	urls := srvURLs(addrs)
	if len(urls) == 0 {
		return nil, fmt.Errorf("no LDAP server found for %q", l.cfg.Domain)
	}

	return urls, nil
}

// srvURLs turns DNS SRV records into LDAP URLs, keeping the priority order.
func srvURLs(addrs []*net.SRV) []string {
	urls := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		target := strings.TrimSuffix(addr.Target, ".")
		if target == "" {
			continue
		}

		urls = append(urls, "ldap://"+net.JoinHostPort(target, strconv.Itoa(int(addr.Port))))
	}

	return urls
}

// connectURL connects to a single LDAP server and performs the initial bind.
func (l *LDAP) connectURL(serverURL string) (*ldap.Conn, error) {
	tlsConfig, err := l.tlsConfig(serverURL)
	if err != nil {
		return nil, err
	}

	conn, err := ldap.DialURL(serverURL, ldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %q: %w", serverURL, err)
	}

	if l.cfg.StartTLS {
		err := conn.StartTLS(tlsConfig)
		if err != nil {
			_ = conn.Close()

			return nil, fmt.Errorf("failed to start TLS on %q: %w", serverURL, err)
		}
	}

	if l.cfg.BindDN != "" {
		err := conn.Bind(l.cfg.BindDN, l.cfg.BindPassword)
		if err != nil {
			_ = conn.Close()

			return nil, fmt.Errorf("failed to bind as %q: %w", l.cfg.BindDN, err)
		}
	}

	return conn, nil
}

// tlsConfig builds the TLS client configuration for a connection.
func (l *LDAP) tlsConfig(serverURL string) (*tls.Config, error) {
	parsed, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL %q: %w", serverURL, err)
	}

	tlsConfig := &tls.Config{
		ServerName:         parsed.Hostname(),
		InsecureSkipVerify: l.cfg.InsecureSkipVerify, //nolint:gosec // Explicit configuration option.
	}

	if l.cfg.CACertificate != "" {
		content, err := os.ReadFile(l.cfg.CACertificate)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(content) {
			return nil, fmt.Errorf("failed to parse CA certificate %q", l.cfg.CACertificate)
		}

		tlsConfig.RootCAs = pool
	}

	return tlsConfig, nil
}

// members returns all values of the member attribute, following AD's ranged
// retrieval (member;range=0-1499) for groups exceeding the value limit.
func (l *LDAP) members(conn *ldap.Conn, dn string, attrs []*ldap.EntryAttribute) ([]string, error) {
	memberAttr := strings.ToLower(l.cfg.MemberAttribute)
	rangePrefix := memberAttr + ";range="

	members := []string{}

	for {
		next := -1

		for _, attr := range attrs {
			name := strings.ToLower(attr.Name)
			if name != memberAttr && !strings.HasPrefix(name, rangePrefix) {
				continue
			}

			members = append(members, attr.Values...)

			if strings.HasPrefix(name, rangePrefix) {
				end, final := rangeEnd(name)
				if !final {
					next = end + 1
				}
			}
		}

		if next < 0 {
			return members, nil
		}

		// Fetch the next chunk.
		req := ldap.NewSearchRequest(
			dn,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0, 0, false,
			"(objectClass=*)",
			[]string{fmt.Sprintf("%s;range=%d-*", l.cfg.MemberAttribute, next)},
			nil,
		)

		result, err := conn.Search(req)
		if err != nil {
			return nil, fmt.Errorf("failed to get members of %q: %w", dn, err)
		}

		if len(result.Entries) != 1 {
			return members, nil
		}

		attrs = result.Entries[0].Attributes
	}
}

// rangeEnd parses an AD ranged attribute name and returns the end of the
// range and whether this is the final chunk.
func rangeEnd(name string) (int, bool) {
	_, spec, _ := strings.Cut(name, ";range=")

	_, endStr, ok := strings.Cut(spec, "-")
	if !ok || endStr == "*" {
		return 0, true
	}

	end, err := strconv.Atoi(endStr)
	if err != nil {
		return 0, true
	}

	return end, false
}

// memberName derives a user name from a member DN without querying the
// server, using the value of its first RDN (for AD, the CN is expected to
// line up with the sAMAccountName). Values that aren't DNs are used as-is
// (e.g. memberUid on posixGroup).
func memberName(member string) string {
	dn, err := ldap.ParseDN(member)
	if err != nil || len(dn.RDNs) == 0 || len(dn.RDNs[0].Attributes) == 0 {
		return member
	}

	return dn.RDNs[0].Attributes[0].Value
}

// resolveMember turns a group member value into a user name.
func (l *LDAP) resolveMember(conn *ldap.Conn, member string, cache map[string]string) (string, error) {
	// Without a user attribute, the user name is derived from the member
	// value itself, avoiding any extra query.
	if l.cfg.UserAttribute == "" {
		return memberName(member), nil
	}

	userName, ok := cache[member]
	if ok {
		return userName, nil
	}

	// The member value is a DN, look up the target entry.
	req := ldap.NewSearchRequest(
		member,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1, 0, false,
		"(objectClass=*)",
		[]string{l.cfg.UserAttribute},
		nil,
	)

	result, err := conn.Search(req)
	if err != nil {
		// Skip entries that are gone or that we can't access.
		if ldap.IsErrorAnyOf(err, ldap.LDAPResultNoSuchObject, ldap.LDAPResultInsufficientAccessRights) {
			cache[member] = ""

			return "", nil
		}

		return "", fmt.Errorf("failed to resolve member %q: %w", member, err)
	}

	if len(result.Entries) != 1 {
		cache[member] = ""

		return "", nil
	}

	userName = result.Entries[0].GetAttributeValue(l.cfg.UserAttribute)
	userName = strings.TrimSpace(userName)
	cache[member] = userName

	return userName, nil
}
