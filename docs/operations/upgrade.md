# Upgrade and rollback

HalimiSOC ships as tagged container images and one static agent binary. There is
no online upgrade orchestration: an operator pulls the new tag, restarts, and
keeps the previous tag for rollback.

## Before an upgrade

1. Take a database backup. This release does not ship backup tooling, and
   PostgreSQL is the only copy of the audit trail, events and incidents.
2. Record the current tag: `docker compose -f deploy/docker-compose.yml ps --format '{{.Image}}'`.
3. Read the commit range between the running tag and the target tag. An applied
   migration is immutable, so a newer binary only ever adds migrations.

## Upgrade

The provided compose file builds from source, so the tag is checked out before
the rebuild. A deployment that consumes the published images instead updates the
tag in its own compose file and runs `docker compose pull`.

```bash
git fetch --tags
git checkout vX.Y.Z
docker compose -f deploy/docker-compose.yml --env-file .env build
docker compose -f deploy/docker-compose.yml --env-file .env up -d
```

The API applies every embedded migration at startup, inside a transaction per
file (`internal/storage/postgres/postgres.go`). A migration failure stops the
process before it serves traffic, which is why the container restart counts as
the health signal for the upgrade.

The agent keeps its spool and read offsets in `StateDirectory`; a package
upgrade does not touch `/var/lib/halimisoc`. Restart it after the API is healthy:

```bash
systemctl restart halimisoc-agent
```

## Rollback

```bash
git checkout <previous-tag>
docker compose -f deploy/docker-compose.yml --env-file .env build
docker compose -f deploy/docker-compose.yml --env-file .env up -d
```

Rollback is safe only when the previous tag does not need a column the newer
migration added; migrations are forward-only. If the newer release dropped or
renamed anything, restore the backup taken before the upgrade instead. There is
no automatic downgrade path, and pretending otherwise would lose data.

## Agent upgrade

```bash
install -m 0755 halimisoc-agent /usr/local/bin/halimisoc-agent
systemctl restart halimisoc-agent
systemctl status halimisoc-agent
```

The enrollment token is a shared bootstrap credential that can enroll more than
one agent; it is not consumed. Afterwards the agent authenticates with the
per-agent token persisted in its state directory (mode 0600).
