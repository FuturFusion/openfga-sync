# openfga-sync
`openfga-sync` is a daemon which synchronizes identity providers with the
OpenFGA stores used by Incus, Operations Center and Migration Manager for
authorization.

It pulls group and role information from a number of data sources and
converts it into OpenFGA relationship tuples, granting users access to the
matching deployments, e.g. Incus projects on every cluster where those
projects exist.

# Data sources
Multiple sources can be active at the same time, their grants are merged.

## AD/LDAP
The LDAP servers can either be set explicitly through a URL or discovered
automatically from the AD DNS SRV records of a domain.

With `sync_roles: true`, all groups below a configurable base DN are
pulled and their names matched against a list of roles. Each role is a
regular expression pattern carrying a set of grants, applied to every
member of the matching groups, with capture groups from the pattern
available in the relation and object templates.

For example, a role with the pattern `^app-(?P<app>.+)-admin$` and grants
`operator` on `project:app-${app}-stg` plus `viewer` on
`project:app-${app}-prod` gives every member of the `app-1234-admin` group
the `operator` relation on the `app-1234-stg` project and the `viewer`
relation on the `app-1234-prod` project.

With `sync_groups: true`, the source instead fills in the membership of
the OpenFGA groups that were granted access in the stores by a third
party, keeping them aligned with the matching LDAP groups (same behavior
as the Rauthy version below).

To keep the number of queries to a minimum, group members aren't looked up
individually by default: the user name is derived directly from the member
DN (its first RDN value, which for AD is expected to line up with the
`sAMAccountName`). Setting `user_attribute` (e.g. `mail` or
`userPrincipalName`) switches to resolving each member entry instead, at
the cost of one query per user. Either way the resulting name must match
what Incus sees at authentication time.

Both paged group retrieval and AD ranged member retrieval
(`member;range=...` on very large groups) are handled.

## Rauthy
With `sync_roles: true`, roles matching a configurable pattern are pulled
from [Rauthy](https://github.com/sebadob/rauthy) (0.35 or newer) and their
JSON metadata read for OpenFGA grants. Grants are keyed by application
type and scoped either globally (all deployments of that type) or to
specific deployments (target names):

```json
{"openfga": {
    "incus": {
        "global": [{"relation": "user", "object": "project:app-1234-stg"}],
        "specific": {
            "cl001": [{"relation": "admin"}]
        }
    },
    "operations-center": {"global": [{"relation": "viewer"}]},
    "migration-manager": {"global": [{"relation": "viewer"}]}
}}
```

Grants without an object default to the server object of their application
type (e.g. `server:incus`). Every enabled user holding a role gets its
grants applied, using their e-mail address as the OpenFGA user name.

With `sync_groups: true`, the source synchronizes group membership
instead: each store is scanned for permission tuples granted to groups
(`group:NAME#member`, typically added by a third party), and the `member`
tuples of every such OpenFGA group are then kept aligned with the matching
Rauthy group, adding and removing members as they join and leave the group
in Rauthy. The group grants themselves are never touched.

Environments are expected to use one mechanism or the other: either the
roles carry the full policy, or the policy is managed externally and only
the group membership is filled in from Rauthy.

# Targets
All the applications share a single OpenFGA instance, with one store per
application deployment (an Incus server or cluster, an Operations Center
or a Migration Manager deployment).

The stores to synchronize are discovered automatically, based on the
`TYPE_NAME` store naming convention: `incus_cl001` is the Incus deployment
named `cl001`, `operations-center_operations-center01` the Operations
Center deployment named `operations-center01`, and so on. Stores that
don't follow the convention are ignored, and newly created stores get
picked up on the next synchronization pass.

With `skip_missing_objects: true`, `openfga-sync` checks which objects
actually exist in each Incus store before writing, based on the object
tuples that Incus itself maintains (e.g. `server:incus` being the `server`
of `project:NAME`). Grants that reference objects which don't exist on a
given cluster are then simply skipped there until a later pass where the
objects showed up, avoiding pointless tuples. Operations Center and
Migration Manager use flat authorization models, so no such filtering
applies there.

# Ownership modes
By default, a local state directory keeps track of every tuple written by
`openfga-sync`, one file per store. Only tuples recorded there are ever
deleted, so tuples managed by the applications themselves or added
manually are never touched. In steady state no OpenFGA write traffic is
generated at all, and the state files are only rewritten when something
actually changed.

With `authoritative: true`, `openfga-sync` instead owns all the user
tuples (`user:NAME`) in the stores: on every pass, each store's tuples are
read back and anything not matching the configured sources is deleted,
including tuples added by hand (the `user:*` wildcard used for
authenticated access is left alone). Tuples granted to groups
(`group:NAME#member`) are never owned, so combining this with
`sync_groups` makes `openfga-sync` authoritative over the group
memberships while a third party keeps managing the group grants. No local
state is kept in this mode.

# Usage
The daemon runs a synchronization pass at a configurable interval:

```
openfga-sync --config /etc/openfga-sync/config.yml
```

- `--one-shot` runs a single pass and exits.
- `--dry-run` only reports the changes that would be made.
- `--debug` enables debug logging.
- `SIGHUP` triggers a configuration reload.

An annotated example configuration can be found in
[doc/config.yml.example](doc/config.yml.example).

# Building
```
make
make test
make static-analysis
```

# Bug reports
You can file bug reports and feature requests at:
[`https://github.com/futurfusion/openfga-sync/issues/new`](https://github.com/futurfusion/openfga-sync/issues/new)

# Contributing
This repository is released under the terms of the Apache 2.0 license.

Fixes and new features are greatly appreciated. Make sure to read our
[contributing guidelines](CONTRIBUTING.md) first!
