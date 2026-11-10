# Durable FileBrowser recycle bin

This change is based on `4750a97cfdf5bd067e04b6b36bf9616f5ada836d`.
It adds an explicit single-file recycle API and makes the ordinary Web delete
confirmation use it. Existing `DELETE /api/resources` and public DELETE contracts
remain available to existing API consumers. Web shares refuse recycling until
the caller opens the file through an authenticated Source. Directory recycling
is deliberately rejected, including mixed batches; successful files are reported
individually and are not sent again when retrying the failed batch members.

## API

All routes use the existing authenticated `withUser` middleware. Source names
are configured display names. Paths are relative to the caller's **current**
SourceScope, with a leading `/`; no filesystem paths or actor identities are
accepted. Operation IDs contain 8–128 ASCII letters, digits, `_`, or `-`.

| Request | Body / query | Result |
| --- | --- | --- |
| `POST /api/trash` | JSON `{source,path,operation_id}` | Durable plain item |
| `GET /api/trash/{operation_id}` | `source` | Current item and reconciliation result |
| `GET /api/trash` | `source`, optional `query`, `offset`, `limit` (1–200; default 50) | `{items,total}`, newest first, including restored records |
| `POST /api/trash/{operation_id}/restore` | JSON `{source,path,restore_operation_id}` | Item plus `restore_attempt` |
| `GET /api/trash/{operation_id}` | `source`, `restore_operation_id` | Item plus the specified historical `restore_attempt` |

Items include `operation_id`, `state`, original `source`, scoped `path`, `name`,
`size`, streaming `sha256`, `actor_id`, `actor`, `created_at`, `updated_at`, and
the latest `restore_operation_id`, `restored_path`, restore actor and error code
when applicable. Filesystem Source keys are persisted privately and never sent
to clients. Restore targets are disclosed only within the current scope and ACL.

Item states are `pending_trash`, `trashed`, `pending_restore`, `restored`,
`failed`, or `manual_reconciliation`. A failed **trash** means that no payload
was moved into the bin. A failed **restore** leaves the item `trashed` and records
a separate failed restore attempt. Each restore attempt retains its ID, target,
actor, timestamps, state and error permanently. After a confirmed failed attempt
the client may use a **new** restore ID. Reusing an earlier ID never executes a
new move, even after later attempts, and changing its target returns 409.

An existing destination returns 409 and a durable `failed/target_exists` restore
attempt. Parents must already exist; restore cannot create directories or
overwrite files. The Web restore dialog defaults to the original path and lets
the user explicitly select another authorized target.

HTTP 400 indicates unsupported/invalid input, 403 current authorization denial,
404 an absent operation/path, 409 a conflict, and 503 an unknown outcome that
must be queried. Storage failures may return 500; clients must query the original
ID before deciding whether to submit a new operation. A successful historical
request can return the current item together with an older failed
`restore_attempt`; clients should inspect the requested attempt's state.

## Storage, durability, and isolation

Every Source stores bytes **and** journals under its own `.filebrowser-trash/`:

```text
Source/.filebrowser-trash/version
Source/.filebrowser-trash/{trash-operation-id}/record.json
Source/.filebrowser-trash/{trash-operation-id}/content
Source/.filebrowser-trash/{trash-operation-id}/restore-{restore-id}.json
```

No trash bytes or journals use the application database, cache directory, `/tmp`,
or a system-disk staging path. Production configuration must keep the Source on
the `/srv/storage` data filesystem. No deployment, mount, or production account
changes are made by this feature.

Linux uses `renameat2(RENAME_NOREPLACE)`: same-filesystem moves are atomic and
cannot replace a concurrent destination. Cross-device or unsupported operations
fail closed; there is no copying fallback or memory-sized file buffering.
Other platforms use rooted no-overwrite link/unlink; an interrupted two-name
result is retained for manual reconciliation. Payload SHA-256 is streamed, and
Linux data and containing directories are synced before acknowledging completion.
Journals are written to the same directory, synced, atomically renamed and synced
again. One FileBrowser process must be the sole writer for a Source.

The durable pending intent precedes any move. Queries reconcile source and
payload/target existence and hashes without replaying a move. Mismatched bytes,
both names, or unexpected missing data become `manual_reconciliation`; neither
copy is removed. If an intent exists but execution never started, a query records
the definite non-move result. Interrupted initialization or damaged metadata is
rejected for operator review; the service does not adopt an unrelated preexisting
directory or automatically clean it.

Delete permission, Source/Scope, ReadOnly and fresh AccessRules are enforced at
the trash boundary. Listing/status additionally require Browse. Restore also
requires Create at the current target and access to the original item. Ordinary
users can act only on their own items; admins still need Source/Scope, operation
permissions and AccessRules. The existing token/user permission intersection and
revocations apply to every request. Roots, directories, symlinks and symlink
parents are rejected by the new operation.

The reserved directory, its descendants and resolved aliases are excluded from
ordinary Access checks, indexing, listing, search, download, archive and writes.
Share archives explicitly skip reserved entries. Extraction cannot write a
reserved entry or create an alias to it. Recursive copy/move/delete and WebDAV
mutations refuse a tree containing reserved storage, including nested Sources.
This guard inspects directory entries and link metadata, not file contents.
The exact name is reserved case-insensitively on all platforms, including Windows
trailing-dot/space and ADS aliases. This intentionally also excludes user-created
directories with that name. Existing general archive ACL behavior is unchanged.

There is no expiry task, cleanup job, empty-bin action, or permanent removal UI.
Restored item and attempt journals remain queryable for platform reconciliation.

## Verification and synthetic preview

Local Windows checks use temporary synthetic fixtures. The new store/HTTP tests
cover ordinary users, token intersections/revocations, current target ACLs,
scope/ownership, same-name protection, recursive isolation, 32 MiB streamed data,
EXDEV rejection, move-before-journal failure, uncommitted restore intent and
historical restore IDs. Frontend tests exercise the original delete confirmation,
share refusal, partial failure, retained unknown-operation IDs and reconciliation.

The existing Playwright general file-actions test now exercises the original
menu → recycle bin → same-name 409 → alternate-path restore, and checks the
restored SHA-256 and unchanged occupant. Directory deletion is explicitly tested
as refused. Existing no-auth and screenshot assertions use the new recycle text.
These are extensions to the existing configuration, not a separate smoke suite.

Commands (Makefile expansions where Make/Git Bash are unavailable on Windows):

```text
cd backend
go test -mod=readonly -timeout=30s ./http ./trash ./common/utils -run 'TestTrash|TestLifecycle|TestMoveThen|TestRejectedCross|TestPendingIntent|TestIntentNot|TestLargeFile|TestRejectsDirectories|TestSymlinkSource|TestListOnly|TestReservedStorage|TestEveryRestore|TestRestoreIntent'
go tool golangci-lint run --path-prefix=backend
go build -o filebrowser.exe .
cd ../frontend
npm run typecheck
npm run lint
npm test
npm run i18n:check
npm run build:docker
```

For a complete embedded binary, build the frontend, copy its `dist/*` into
`backend/http/embed/`, then build the backend (the normal Makefile build does
this on supported shells). English fallback strings are included for all locales;
Simplified Chinese is translated. No dependencies or lockfiles are changed.

The fixed baseline also fails the existing Windows Unix-path/executable-bit
tests. Repository-pinned backend lint reports 18 existing baseline findings;
these are kept separate from feature findings. Linux CI and production acceptance
must be reported independently from local targeted checks.

Create a loopback-only synthetic preview with an explicitly built binary:

```powershell
pwsh -NoProfile -File tools/recycle-preview.ps1 -Binary backend/filebrowser.exe -Port 18089
```

The script uses only ignored `.local/recycle-preview/`, preserves previous
fixture files/journals, strips inherited FileBrowser settings from its child
environment, and prints its helper PID. It never selects a production Source,
opens a browser, or removes files. Stop only that displayed helper PID when done.

Browser access to **http://127.0.0.1:18089** requires the exact origin to be
authorized. On November 10, 2026, auto-review rejected that origin, so the manual
browser menu flow remains **unverified**. The isolated preview returned health
200 before that rejection and was stopped afterward. No alternate browser,
origin, CDP session or indirect browser channel was used to bypass the gate.
