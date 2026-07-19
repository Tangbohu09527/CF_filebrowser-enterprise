# Failure drills

Run destructive drills only on an isolated Debian staging host with disposable
paths. Never point these commands at production data. The offline subset runs as
part of `make validate-deployment`:

```bash
./scripts/tests/failure-drills.sh
```

The offline behavioral subset exercises missing config, missing JWT secret,
missing bootstrap secret, read-only database mode, an impossible cache
free-space threshold, a corrupt restore checksum, and image registry rejection.
It also runs static guard assertions for interruption recovery, schema-2 backup
metadata, durable restore journaling, automatic upgrade rollback, data-aware
rollback, and Nginx backend connectivity. Those static assertions are not a
substitute for the Debian staging behavior drills below.

## Debian staging matrix

Use a disposable deployment produced from synthetic files and a throwaway DB.
Capture `docker compose logs`, script output, and the resulting manifest for each
drill.

| Drill | Injection | Required result |
| --- | --- | --- |
| Missing config | Move the staging `config.yaml` aside, then run validation. | Validation fails inside `stack.sh` before its `compose up`; systemd start fails and no container starts. |
| Missing secret | Move either stable secret aside. | Entrypoint exits before the binary runs. |
| Database read-only | Remove write mode for the FileBrowser UID/GID. | Validation fails; direct start becomes unhealthy without Nginx starting. |
| Cache full | Set `MIN_CACHE_FREE_MB` above available space, then fill only the disposable cache filesystem. | Validation fails before start; an already running app reports write failures without corrupting Bolt. |
| Backup interrupted | Send `SIGTERM` to `backup.sh` after services stop and before atomic rename. | `.incomplete` is removed and the prior service state is restored. No final backup directory appears. |
| Restore hash failure | Alter one byte in a copied payload. | Dry run fails at `sha256sum -c`; no target path or service changes. |
| Restore target is a mount | Bind-mount one disposable target onto itself and run the default restore dry run. | Dry run rejects the mount before any service or path change because an atomic sibling swap is impossible. |
| Restore bundle permissions | Make a copied bundle or payload group-writable or non-root-owned. | Restore rejects it after hash verification and before any tar extraction or target change. |
| Restore interrupted | Send `SIGKILL` after a registered target is renamed and before health validation. | Stack start fails closed while `/var/lib/filebrowser-enterprise-lifecycle/restore-journal.tsv` exists. `/usr/local/sbin/filebrowser-enterprise-recover` shows only allowlisted paths; adding `--apply` reverts them in reverse order. Business requests receive `503` until commit and production proxy promotion. |
| Restore journal corruption | On a disposable host, replace one copied journal target with `/etc/passwd`, leaving the real transaction paths untouched. | Preview and apply reject the journal before any rename because the target/original/replacement tuple is outside the allowlist. Restore the original copied journal to continue the drill. |
| Upgrade health failure | Use a pinned disposable image whose health endpoint fails. | The maintenance entry point never proxies business traffic; `upgrade.sh` invokes `rollback.sh`; old image and matching pre-upgrade DB return healthy. |
| Upgrade image-pin window | Power off after `backup_path` is durable or after `.env` changes, but before `starting-candidate`. | Durable `preparing`/`backed-up` proves the candidate never opened Bolt. Rollback restores the old pin and verified old service without creating a falsely labeled roll-forward backup. |
| Upgrade reboot window | Power off after state becomes `starting-candidate`, then boot staging. | Docker does not auto-restart transaction containers; systemd/`stack.sh`, backup, and validation reject the non-terminal state. The recorded `rollback.sh --state ... --apply` path restores image plus matching data. |
| Rollback pre-journal window | Power off after state becomes `rolling-back` but before the restore journal exists. | `.env` still pins the new image; lifecycle guards reject start. Resume reuses the same verified new-image roll-forward point and creates a journal before installing the old pin/data. |
| Rollback post-journal window | Power off after `rollback-data-restored` is durable and before terminal commit. | If journal recovery returned new/new, restore repeats with the existing roll-forward point. If the journal was already removed, old/old is revalidated and only production promotion continues. |
| Manual rollback | Roll back the last successful disposable upgrade state. | One roll-forward backup is created and retained, old image plus matching data are restored, cache is rebuilt, and systemd ownership is requeued when needed. |
| Backend unavailable | Stop only FileBrowser after the stack is healthy. | Nginx container health turns unhealthy and runtime validation reports backend connectivity failure. |

For backup interruption, verify the service recovery trap both after `SIGTERM`
and after forcing `tar` to return non-zero. For upgrade/rollback, compare the
running image ID, `filebrowser version` Git SHA, database hash, and probe-file
content against the recorded state and manifests.

For restore interruption, first run
`/usr/local/sbin/filebrowser-enterprise-recover` without `--apply` and record its
preview. Confirm that normal `stack.sh start` refuses to run. Then add `--apply`
and verify, in order: the old image pins are restored, FileBrowser becomes
healthy, maintenance Nginx returns `503` for business paths while its TLS/backend
checks pass, the journal is removed, production Nginx is promoted, and runtime
validation passes again. If FileBrowser health is injected to fail, Nginx must
remain stopped and the journal must remain available for a second recovery
attempt.
