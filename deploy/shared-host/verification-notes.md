# Verification notes

## CI compatibility and whole-package budgets (2026-09-07)

These are observed failures and repair inputs, not a claim that the repaired jobs passed.
Failed source SHA: `dbd8244c752a3c3c5a3d3dd9443462a850b27362`.

| Observed job | Failure evidence | Interpretation |
| --- | --- | --- |
| [regular / test-backend](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34097679989/job/101664842887) | `go test -race -v ./... -timeout 30s`; HTTP package exceeded 30 seconds while an existing preview permission test was running | Whole-package budget exhausted; product permission and timeout assertions remain unchanged |
| [regular / lint-backend](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34097679989/job/101664843190) | `stable` resolved to Go 1.27.1; golangci-lint v2.1.6 reported export data version 4 greater than maximum supported version 2 | Analyzer/toolchain incompatibility; subsequent undefined errors followed failed type loading |
| [shared-host / source-regression](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34097679983/job/101664843399) | `make test-backend` used `-race -timeout=10s`; both auth and HTTP packages timed out | Keep the full race/security suites and increase their whole-package execution budget |

In the [first regular backend job](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34096771279/job/101662066548),
source `cd95d6d4f27a4cd8e33cd1e9f9565f9d150efbfe`, existing
`TestJSONAuth_NoTimingAttack` passed in 14.52 seconds, already longer than the
Makefile's 10-second whole-package limit. The four new `TestClientNetworkListener`
tests passed (0.00 seconds each). These individual results do not establish a passing full suite.

| Configuration | Before | After |
| --- | --- | --- |
| Four regular setup-go steps and shared-host source-regression setup-go | `stable` (resolved to 1.27.1 in these jobs) | Pinned `1.26.8` |
| Regular golangci-lint | `v2.1.6`, installed with `goinstall` | `v2.12.2`, still `goinstall`, matching the tool already pinned in `backend/go.mod` |
| Makefile backend package test | `-race -timeout=10s ./...` | `-race -timeout=5m ./...` |
| Regular backend package test | `-race -v ./... -timeout 30s` | `-race -v ./... -timeout 5m` |
| Regular backend test / lint job limits | Unspecified (GitHub default limit) | Explicit 20 / 15 minutes |
| Shared-host source-regression job | 45 minutes | Unchanged, 45 minutes |

Compatibility evidence: this repository requires Go 1.25.0 and already pins its
Lint tool to v2.12.2. The [official Lint changelog](https://golangci-lint.run/docs/product/changelog/)
records Go 1.26 support from v2.9.0 and Go 1.27 support only from v2.13.0.
[The v2.12.2 module](https://github.com/golangci/golangci-lint/blob/v2.12.2/go.mod)
also requires Go 1.25.0. [Go release history](https://go.dev/doc/devel/release)
records Go 1.26.8 released on 2026-09-01; the
[official actions/go-versions manifest](https://github.com/actions/go-versions/blob/main/versions-manifest.json)
was checked for its Linux x64 package. The selected combination retains the repository's
existing tool dependency and follows the [Lint compiler compatibility requirement](https://golangci-lint.run/docs/welcome/faq/).

This limited CI exception was explicitly authorized by the user. No `go.mod`,
`go.sum`, frontend dependency/lock file, AGENTS, product timeout assertion, test
assertion, or Lint rule changed. All workflow jobs and steps remain; no skip,
continue-on-error, nolint, or narrowed check selection was introduced.

Local verification: Python/PyYAML parsed both workflows and compared their full
structures with HEAD, allowing only the versions and budgets listed above. The
Makefile comparison, accounting for native checkout line endings, confirmed only
the package timeout changed. `git diff --check` passed. This Windows machine has
no Go/Docker runtime; local static checks are not reported as backend or image
execution. Full test/Lint/shared-host results must come from actual CI on the
next pushed source SHA.

## Image commands stay on the local build host

The image helper previously inherited the caller's Docker daemon/context and
builder selection. Added subprocess-mock regressions reproduced 17 failing
subcases before the fix: eight Docker operations under both inherited and
explicit poisoned environments, plus the Compose builder selection check.

Every image-helper Docker command now explicitly uses
`--host unix:///var/run/docker.sock`; daemon context/TLS and remote BuildKit
selectors are removed from its child environment. `BUILDX_BUILDER=default` and
Compose `build --builder default` select the local Docker Engine builder.
`DOCKER_CONFIG` is preserved for normal registry credential helpers. No caller
environment or host configuration is changed, and pinned base digests, source
SHA, architecture checks and actual Image ID recording remain covered.

The [official Docker CLI reference](https://docs.docker.com/reference/cli/docker/)
describes the daemon/context selection controls; the
[Docker builder driver documentation](https://docs.docker.com/build/builders/drivers/docker/)
identifies the default driver with the BuildKit embedded in Docker Engine.
The [Compose v2.20.0 source](https://github.com/docker/compose/blob/v2.20.0/cmd/compose/build.go)
was checked: both `--builder` and `BUILDX_BUILDER` already exist at the supported
minimum version, so the minimum requirement was not raised.

Executed locally with Python 3.12:
`python deploy/tests/test_shared_host_image.py` (13 tests passed after the fix)
and `git diff --check` (passed). These tests mock subprocess execution; they did
not connect to a Docker daemon or publish an image. The next fixed-image CI run
must provide real build execution evidence for this change.

## Independent checks remain visible after a failure

The shared-host workflow now places the unchanged `make test-backend
lint-backend` command in a separate `backend-regression` job with a 30-minute limit. Its failures
continue to fail the workflow. The existing frontend, independent FileBridge and
`make test-playwright` commands remain in `source-regression`. A backend failure
therefore stays red while independent UI/client checks can actually run. No
command, assertion or scanner was removed; no continue-on-error was added.
This job organization does not change repository branch-protection settings.

## Actual b614e638 run and remaining failures

Source SHA: `b614e6381916b4f0adccd73ca07be6b52a77c260`.
[The real image/VM job](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34098619849/job/101667724118)
built the frontend/backend image, verified the official Debian cloud checksum,
published to the isolated TLS registry, and booted Debian 13.6 with systemd.
VM 1 installed Docker 29.8.0 / Compose 5.5.1, mounted the independent ext4
`/dev/vdb`, and pulled the fixed registry digest. It then failed the cross-host
Image ID equality assertion before FileBrowser preparation. A/B acceptance is
not complete; no administrator initialization, host reboot or restore is claimed
for this run. The sanitized artifact records the precise failed stage.

The configured two-VM budget was 4 GiB RAM and 84,826,357,760 bytes total sparse
virtual disk capacity (including the 3 GiB cloud base and seeds), below the
8 GiB / 80 GiB caps. QEMU used TCG. Host preflight reported 15,409,868,800 bytes
available memory and 87,321,706,496 bytes free disk. No Windows VM runtime was
installed and no Windows global configuration was changed.

[The complete backend test job](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34098619862/job/101667723866)
finished the HTTP package in 99.309 seconds. The three failures were existing
WebDAV COPY cases: new target with Create, overwrite with Modify/Delete, and
replacement of a symlink entry without changing its target. HTTP succeeded,
but the resulting destination was unreadable because the FileInfo wrapper
returned mode zero before global file modes were initialized. The minimal fix
uses the already-existing effective permission helpers; existing security
assertions remain. The new direct mode test checks defaults and configured
modes, so root/Windows cannot hide a mode-zero regression. At source
`c86c8cf54b1687caa74c5e3470354f5ceaa194be`, both complete backend race-test
entries passed: [regular backend](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34100236777/job/101672768936)
and `make test-backend` in [shared-host backend regression](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34100236812/job/101672769879).
The latter job remains failed because its subsequent full Lint reports the
78 unchanged-baseline findings; passing tests do not imply passing Lint.
The four new TCP-source listener tests and bootstrap-password log regression
passed in this job.

[The complete Lint job](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34098619862/job/101667724154)
ran successfully as an analyzer and reported 79 findings. One was an unchecked
SetDeadline result in this task's new listener test; that check was corrected
without increasing the one-second socket deadline. The other 78 locations are
in unchanged integration-baseline code across 19 files (source comparison,
not a claim of a separate baseline Lint execution). Their broader repair needs
an explicit scope decision; full Lint remains a failing check until resolved.

## Cross-store image identity verification

[Docker documents](https://docs.docker.com/engine/storage/containerd/) that fresh
Engine 29 installations use the containerd image store. The
[Moby containerd inspect implementation](https://github.com/moby/moby/blob/master/daemon/containerd/image_inspect.go)
uses the target descriptor digest for its Image ID and reads the configuration
separately. This differs from the classic store's configuration-based ID.
The failed b614 run did not retain the guest ID, so this source evidence alone
is not a claim to have observed that exact value in that run.

The next run verifies the published raw manifest/config bytes against their
SHA-256 digests, checks the Linux amd64 platform, revision label, populated
runtime configuration and root filesystem diff IDs, and records both builder
and guest IDs. An ID must belong to the verified config/manifest/index graph.
Each guest additionally creates, but never starts, one precisely scoped
network-none identity probe with no project mounts; its Image must match that
guest's recorded local Image ID. Only that probe container is removed. Both
clean Debian guests must resolve the same local ID before backup/restore.
Actual CI execution is required to confirm this transfer, and failure evidence
is saved before each comparison. No registry, TLS or digest check is disabled.

## Existing Sharing Playwright setup selector (2026-09-07)

[Source-regression job 101672769623](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34100236812/job/101672769623),
source `c86c8cf54b1687caa74c5e3470354f5ceaa194be`, failed in the first existing
Sharing Docker test entry point. The server was listening after 0.37 seconds;
login succeeded and the administrator's root share request returned HTTP 200.
At 38.80 seconds the global setup timed out waiting for the old input label
`allow creating and uploading files and folders toggle` at line 73.

The handoff baseline `48380c3f31cb37b01d0c05b8db0cfa49680a17f9` already contained
this mismatch: `Share.vue` uses `data-testid="configured-capabilities"` with
stable input labels `create` and `modify`, while global setup used old translated
sentences. The existing `share-capabilities-ui.test.js` also verifies the current
labels, their enabled state and their initial unchecked values.

Only the existing `frontend/tests/playwright/global-setup.ts` was changed: scope
the two locators to the capability editor, retain attachment checks and real
slider clicks, and assert enabled/unchecked before each click and checked after.
No product behavior, timeout, test configuration, dependency or existing test
assertion was removed or relaxed.

Local `node --experimental-strip-types --check frontend/tests/playwright/global-setup.ts`
and `git diff --check` passed. The existing focused command
`npm test -- --run src/components/prompts/share-capabilities-ui.test.js` was
attempted in `frontend` but could not execute because this checkout has no
`node_modules`/Vitest. No dependencies were installed. The corrected full
`make test-playwright` run still requires the next actual Docker CI execution.

## Actual runtime identity checks and local verification limits

The VM harness now checks the running image under its configured service user
without a `docker exec --user` override: numeric UID/GID including PID 1,
dependency versions, the embedded source commit, byte I/O in fresh owned
temporary files in files/data/cache, denied root/config writes and read-only
protected mounts. It checks Secret access metadata without reading or exporting
Secret values. The sanitized record is saved before assertions. This new stage
requires the next actual VM run; its Python counterexamples are not runtime proof.

Local `python -B -m unittest discover -s deploy/tests -p 'test_shared_host_*.py'`
ran 87 tests: 84 passed and three failed because this Windows checkout has no
Docker CLI (two real Compose merge tests and the validator integration test).
No assertions were skipped and no Docker installation was performed. The
previous source c86c8cf passed the complete
[CI deployment validation job](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34100236812/job/101672769802),
including actual Compose validation and every tracked Shell file's syntax.
The new runtime assertions still require CI at their own source SHA.

## Actual cross-store transfer passed; installation stopped at TLS verification

At source `c86c8cf54b1687caa74c5e3470354f5ceaa194be`,
[real image/VM job 101672769848](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34100236812/job/101672769848)
completed the full frontend/backend build, isolated TLS registry publication,
both clean Debian 13.6 systemd boots, Docker 29.8.0 / Compose 5.5.1 installation,
independent ext4 `/dev/vdb` mounts, and both empty-store registry pulls.

The builder's configuration-based Image ID was
`sha256:9ca7d205a8b8f3d75844a8dfd4d7f1f4e400e13b14e2362f8b4a95701033d2d2`.
Both guests recorded the manifest-based local Image ID
`sha256:8d59866975356e518572bd55851a4c16202520903f1d0599de5e856a5bca5fe4`,
matching the published registry digest. Raw manifest/config checksums, source
revision, runtime configuration and every filesystem diff ID passed. Each
never-started isolated container matched its guest's actual Image ID. These are
observed values, unlike the uncaptured guest ID in the earlier b614 failure.

The run then stopped at `formal-empty-root-prepare`: OpenSSL returned exit 1
during TLS input validation. No first start, administrator initialization,
application LAN/API/UI, reboot or restoration passed in this run. Existing data
was retained; no database reset or certificate-verification bypass was used.
The sanitized artifact includes source/image/environment and exact stage; no
Secret, sensitive backup or VM disk was uploaded.

## TLS-input failure reproduction and correction

Real local OpenSSL 3.5.6 (7 Apr 2026) reproduced the failure: `pkey` with
`-passin file:/dev/null` rejects EOF before parsing even an unencrypted key.
The explicit empty `-passin pass:` accepts that key without prompting or putting
a password in arguments. The installed-deployment validator already uses this
form. A second negative case showed that combined `x509 -checkend -checkhost`
returned zero for the wrong DNS name; `verify -verify_hostname` rejected it with
exit 2. Preparation now verifies chain and DNS/IP name with `verify`, checks
24-hour remaining validity separately, and retains exact public-key comparison.
Fixed phase names add diagnostic context without reflecting OpenSSL output or
Secret values. No TLS verification was removed.

Seven new real-OpenSSL tests initially produced two failures and two errors.
After only the passphrase-input fix, the wrong-DNS case still failed because no
DeploymentError was raised. With both corrections, all 22 lifecycle tests passed
(the original 15 plus seven real certificate/key cases). Real VM preparation
still needs to pass at the next fixed source SHA.

## Existing private-source Sharing UI regression

At `b461f99e3670cb342fa71cedd002afef515d64f3`,
[source job 101676832148](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34101372332/job/101676832148)
ran the existing Sharing suite: 12 passed, one failed. The private-source case
expected the previous detailed UI text; actual notifications contained only
`Error creating share`, exactly as the integration baseline's `api/share.js`
already specifies. The setup selector repair therefore passed its actual use.

The existing private-source test now waits for the actual POST response before
asserting status 403 and the unchanged specific private-source refusal reason
in its JSON body, then checks the current error notification. It retains the
zero-share-row assertion and original console/API error counts. It does not
replace a security denial check with a generic message alone or change product
behavior, retries or timeouts. Its corrected full Playwright run is pending.

## Missing-mount and blank-restore evidence strengthened

A counterexample demonstrated that a new boot ID plus a stopped FileBrowser
could be observed before Docker had restored anything. The missing-mount test
now observes normal Docker/sentinel autostart for at most 180 seconds, without
starting either service or touching an inactive Docker socket. Every observation
checks the absent mount, underlying system disk, no business path and no running
FileBrowser. It then checks exact pre-reboot container IDs, requires an explicit
start of that same FileBrowser container to fail, and repeats the no-write checks
before the original late-mount/formal-start flow. Last state and fixed error
categories/hashes are retained before assertions. No product timeout changed.

Blank restoration now reads the actual protected recovery record and compares
its archive/source/image/identity fields with independently captured inputs.
Both installed storage markers must agree with the recovered value and differ
from the old value. Only hashes leave the guest. Missing/duplicate/modified
evidence, unsafe modes and unchanged/mismatched identities fail the probe.
Local lifecycle (22), VM harness (19) and restore-evidence (10) tests passed,
along with syntax of the changed existing Playwright test. These counterexamples
strengthen acceptance; they do not replace actual missing-disk boot or live
blank-recovery evidence, which is still pending.

## Acceptance client aligned with the existing product contracts

Source inspection and focused counterexamples found two API-client mismatches:
`userPutHandler` returns 204 for successful permission updates (also asserted by
the existing Go audit user-action test), whereas the new client expected 200;
the audit query DTO exposes schema version in event metadata, not the database
event's top-level `schemaVersion`. The permission update now accepts exactly
204, and persists expected grants only after that result. Audit checks use the
actual DTO and retain metadata version, actor/source/path/method, terminal
success/denial, redaction and persisted-event assertions.

The successful-204/noncontract-200 tests first produced one error and one
failure. Removing the invented top-level field from the audit fixture first
failed `bridge_audit_terminal_success_upload`. After the client corrections,
all 12 protocol-client unit tests passed. These are counterexamples and source
contract checks, not a claim of completed live FileBridge or WebDAV protocols.

The ordinary UI account retains the product default `editorQuickSave=false`.
The deployment UI test now uses the existing overflow menu's Save action, as
the repository's other UI tests do, instead of expecting an optional shortcut.
It retains the real save response, downloaded-byte digest, rename and delete
checks; no fixture preference, permission or product behavior changed. Syntax
passed; live browser execution still requires the fixed-image VM run.

## Precise installed-validator diagnostics

At `a1fab56b1270bafbb0535bff559f7c21b73c420c`,
[VM job 101680879209](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34102532477/job/101680879209)
passed the same verified two-VM image transfer. Preparation advanced beyond
OpenSSL input checking but stopped when the installed-deployment validator
returned exit 1. The protected child output was suppressed, so this result did
not identify the exact rejection predicate; it is not a successful installation.

The validator now emits fixed phase/kind/line/exit markers. Only its dedicated
lifecycle invocation may extract the complete strict marker grammar and phase
allowlist; arbitrary command output, human messages and values stay suppressed.
All existing validation predicates remain. Local lifecycle tests (24), relevant
real Shell/embedded-contract diagnostic tests (4), `bash -n` and diff checks
passed. The actual rejection location remains to be established by the next VM
run; no dependency or validation threshold was changed on a guess.

## Existing Settings UI startup and persisted JWT signing key

[Source job 101680879155](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34102532477/job/101680879155)
at a1fab56b passed all 13 existing Sharing browser tests in 33.7 seconds.
The subsequent Settings image initialized its own fresh database through a CLI
command, exited, and started the server. Login, self and settings requests
returned 200, but the first authenticated resource read returned 403; the
unchanged five-second page-title assertion then failed. This was not reuse of
the Sharing image or a request to grant the administrator extra permissions.

Source tracing found that first initialization saved a generated signing key,
while reopening a database with no explicit key left the runtime key empty.
The authenticated-read guard correctly rejects an empty key. Initialization
now loads only the same database's saved JWT key when no explicit config/env
key exists; absent or unreadable saved keys close the database and fail with a
fixed error. First setup also preserves an explicit key instead of replacing
it. Other current configuration and persisted data are not restored wholesale.

Synthetic Bolt tests were added before the fix for generated/explicit first
setup and real close/reopen, explicit restart override without rewriting saved
settings, and missing/empty/corrupt saved keys. They check administrator hashes
and permissions, no replacement key, no private-content error, unchanged stored
bytes and a bounded reopen proving the failed path released the lock. This
Windows checkout has no Go/gofmt, so these new Go tests have not run locally;
full backend race tests, Lint, format checking and existing Playwright must run
in CI at the new source SHA. Existing migration and bootstrap-log assertions
remain unchanged.

## Generated signing key serialization: actual failing regression

At `52136fcac5075d2a537bed557edb7f9151caccfb`,
[backend job 101689135180](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34105398684/job/101689135180)
failed the new storage package tests in 9.515 seconds: generated first-setup key
was not equal to its stored value, and the explicit-restart test found the same
initial discrepancy. Explicit first setup and missing/empty/corrupt persisted
key cases passed. The corresponding shared-host backend job also failed; this
SHA is not a passing backend result. Format checking passed and compatible
Lint continued to report the same 78 integration-baseline findings.

`utils.GenerateKey` returned a string containing 64 raw random bytes. Storm's
default JSON codec replaces invalid UTF-8 bytes while saving that string,
changing the signing key. Only the first-generation return value now uses hex
encoding of the same 64 random bytes. Existing keys are neither regenerated nor
re-encoded. The strict storage equality, explicit override, restart and
fail-closed assertions remain, with an additional hex-length and JSON round-trip
test. Local diff checks passed; actual Go execution remains pending CI.

The dependency preparation tutorial now includes signed official Docker APT
setup, explicit package-version inputs, existing-installation refusal and normal
Docker service autostart. Its four outer/embedded Shell snippets passed syntax
checking. No installation was run on Windows, and these syntax checks do not
establish a clean Debian installation result.

## Precise 52136fca VM and existing browser results

[Fixed-image job 101689134762](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34105398656/job/101689134762)
at `52136fcac5075d2a537bed557edb7f9151caccfb` built the real image
`sha256:7c135ca521973d60b1ade5dce60f327eb1bf8193ebce7c869feec5d8706ff0a1`.
The isolated TLS registry manifest was
`sha256:cefb7f78fc177223af640de95733049d6abe1ba45225f5e18955d2579f9f1e59`.
Both actual Debian 13.6/systemd guests completed fixed-source checkout,
independent ext4 storage and verified image transfer. Formal preparation failed
at the Compose-contract block, relative line 331: the rendered LAN healthcheck
comparison. This precise failure does not establish the rendered value or a
passing installation. Initialization, functional checks, reboots and recovery
were not reached. The sanitized VM result is retained locally; no protected
backup, credentials or VM disk was downloaded.

[Existing Playwright job 101689134931](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34105398656/job/101689134931)
at the same SHA passed Sharing 13/13 in 37.7 seconds and Settings 25/25 in
57.2 seconds. NoAuth then passed 21 and failed eight tests in 4.4 minutes.
Failures include nested navigation/preview requests missing a path separator,
plus file-action/indexing checks. The full browser run remains failed; later
projects were not reached. No title timeout, error-count assertion or test was
removed to classify these results as passing.

## Follow-up fixes and stronger network evidence

At `8b04af77958ecc91f0d106fd42fe534e36e5340a`,
[regular backend job 101693501369](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34106777472/job/101693501369)
passed the full existing race-enabled suite, including all new signing-key tests.
Storage completed in 10.095 seconds and HTTP in 131.745 seconds. Format, frontend
tests/Lint, translations and docs passed. Lint still reported exactly 78 baseline
findings; the workflow remains failed.

The Compose failure was reproduced against the existing exact assertion:
reviewed escaped healthcheck text failed while seven malicious changes were
rejected. Both [Compose 2.20](https://github.com/docker/compose/blob/v2.20.0/cmd/compose/config.go)
and [Compose 5.5.1](https://github.com/docker/compose/blob/v5.5.1/cmd/compose/config.go)
re-escape dollars after serializing config output. The comparison now requires
the exact reviewed escaped string, retaining strict CA/hostname/HTTPS, health
body and command checks. Eight cases and existing diagnostic tests passed
locally. A real LAN Compose render/validator test was added to the existing
assets suite; it awaits CI because Windows has no Docker.

The noauth nested-path failure was traced to `adjustedData`, which concatenated
parent path and child name without ensuring a separator. Backend normalized
paths may lack a trailing slash. Three actual-function counterexamples reproduced
the observed bad paths before repair. Reusing the existing `joinPath` passed six
cases, including root, trailing slash, nested paths, hash and Chinese/space names.
All original unit assertions remain, with six new cases. JavaScript syntax passed;
this local function probe is not Vitest or Playwright, which must rerun in CI.

A LAN test counterexample showed that curl connection error 7 incorrectly
satisfied the old generic-failure negative probe. The real-VM probe now requires
successful TCP connection with exact source/peer, then prompt TLS EOF/reset from
the denied peer; timeout, certificate/protocol errors and successful TLS all fail.
Allowed-source strict HTTPS succeeds before and after, wrong CA requires curl 60,
and forged forwarding headers are tested over valid allowed-source HTTPS.
A denied peer cannot transmit HTTP headers because refusal precedes TLS; no
plaintext request is sent to misrepresent that boundary. The existing VM harness
suite passed 27 tests locally, including eight new counterexamples. This is not
actual Docker LAN-path evidence. All 22 tracked Shell files passed individual
`bash -n` checks; no unrelated newline normalization was performed.

## Actual a42d1bd5 regression results and remaining UI repairs

At `a42d1bd5320ff088b65f470119b900c7a12b2e4d`, the
[existing deployment job 101695837538](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34107517391/job/101695837538)
passed all 130 deployment tests, including the new real LAN Compose rendering
and validator case. [Vitest job 101695838354](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34107517449/job/101695838354)
passed 115 tests in 17 files, including all 12 API utils tests. The complete
backend suite, frontend Lint, format, translations and docs passed; backend Lint
remains failed. These results are bound to this SHA, not later changes.

The preceding 8b04af77 VM job 101693501549 completed with the same pre-fix
Compose-contract line 331 failure. Its real image was
`sha256:00cab8318cf5580f9761338ce560c0a62cbb9fa8b9bbde307f2b07ad0e1bf9db`,
with isolated registry digest
`sha256:2feb90e0e5cc50f4e15309be23061f5abca0f47371bf80441fadfecf827b747e`.
Initialization and later A/B stages were not reached. The a42d1bd5 VM job is the
first running with the repaired comparison; its result is still pending.

Two existing noauth expectations were traced to current, intentional behavior:
current-directory selection displays the normalized path without a trailing
slash, and inaccessible reads return the existing redacted error message.
The tests now use those exact values while retaining all visibility, success,
notification and error-count checks. Both real copy requests and their complete
success DTOs, final destination file visibility, and the actual inaccessible
read status/DTO are additionally asserted. Both files passed Node syntax and
diff checks. Actual browser execution of these edits is pending.

## Resource display boundary and root-share setup diagnostics

The two noauth directory-size assertions remain unresolved. Source review found
that simply retaining cached folder aggregates after filtering can expose the
capacity of denied descendants: `CheckChildItemAccess` filters children without
recomputing the global aggregate. The speculative uncommitted folder change was
withdrawn before commit. Shared identity/filter functions retain their original
fresh filesystem sizes; the existing directory-size UI expectations are intact.

A separate file-size mismatch can be repaired safely: after the resource GET's
final authorization/filter/audit-target checks, directory JSON listings now apply
the existing source logical/physical display rule to already refreshed regular
file sizes. File detail, preview and WebDAV Readdir keep real byte lengths; their
shared filter is unchanged. New tests cover file boundaries, fresh changes,
deletions/type changes, withdrawal of Browse and suppression of direct/nested
hidden capacity. Local diff checking passed; actual Go execution is pending CI.
A safe directory total needs bounded descendant authorization and an explicit
unknown/partial contract, not a bypass or unbounded recursive listing.

[Source job 101697741673](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34107517392/job/101697741673)
at a42d1bd5 passed Sharing 13/13 in 35.3 seconds, then failed Settings global
setup before tests began: the root Share prompt content was absent. Two earlier
shares and root resource reads returned 200, but no root share GET was observed.
This is not evidence that the new child-path join caused the failure or that the
NoAuth repairs passed. Settings setup now scopes the click to the visible root
context menu, asserts no selection and captures the real root share GET. It
requires 200 after the existing helper returns, retaining the exact root-path
assertion and the original two-/twenty-second helper boundaries. Failure output
contains only fixed browser-error categories, prompt counts and a fixture-path
allowlist. Syntax/diff checks passed; the original fault still needs real CI
revalidation and is not declared solved by added synchronization alone.

## Actual a42d1bd5 installation and LAN results; strict certificate repair

[Real VM job 101697741297](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34107517392/job/101697741297)
ran two clean Debian 13.6/systemd guests with independent disposable ext4 data
volumes. Formal preparation, first healthy start, administrator login, controlled
stop/bootstrap removal/same-image restart, second administrator login and
idempotent preparation passed. Runtime UID/GID/PID 1 were 10001; expected writable
mounts, read-only configuration/root, required tools and absent bootstrap were
verified. This was actual installation, not preconfigured fixture state.

Second-VM access over Docker's published path passed: allowed-source HTTPS/UI
before and after returned 200; wrong CA was rejected with curl 60. The denied
192.0.2.99 peer completed TCP to verified 192.0.2.11, then received TLS EOF in
23 ms without completing a handshake or sending application bytes. Spoofed
forwarding headers did not change the allowed TLS peer's access.

The builder/config image ID was
`sha256:857e447e2a0548c1f4476da0b0dda555d489b39e094e16e968195ed9f5b6a783`;
the isolated registry manifest and verified guest runtime image ID were
`sha256:a303078bf146318306b1d5b080743c15a094103d339e70a52903c1f45b5d4d73`.
Different Docker image-store identity representations were checked against the
same content. The sanitized `vm-result.json` is retained outside Git.

The job failed at `initial-real-api-exercise`, request 1 (administrator login),
with only the historical generic TLS/HTTP transport error. File/API permission,
protocol, browser UI, restart, backup and blank restore stages were not reached.
This does not establish complete A or B acceptance.

A subsequent local reproduction with OpenSSL 3.5.6 and Python 3.12.10 established
that the same fixture CA passed ordinary verification but failed strict X.509
verification with code 92 at depth 1: missing CA Key Usage. Python 3.13 enables
strict verification in its default client context. This is a confirmed fixture
defect, not a recovered error code from the historical job. Disposable CA/leaf
certificates now specify their signing, basic constraints, identifiers, SAN and
server-auth extensions. Strict flags, CA validation and hostname checks remain.
Real strict certificate/loopback TLS tests and protected transport diagnostics
passed 45 targeted tests; the latter export only fixed categories and bounded
integer codes, suppressing original exception text and chains. Real API
revalidation is pending the next fixed-image CI run.

## Actual aa1bb690 source regression and accurate audit boundary

At `aa1bb69073729e31f425a121c97c5320fcccd3c8`, the complete backend race suite
passed (HTTP 99.465 seconds), including every physical/logical resource display,
fresh filtering, permission withdrawal and denied-directory aggregate regression.
Format, frontend checks and deployment validation passed; backend Lint still
reports 78 findings. No rule, assertion or scan scope was disabled.
[Source job 101702675921](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34109331621/job/101702675921)
passed 115 frontend unit tests, Sharing 13/13, Settings 25/25 and Noauth 27/29.
The only two Noauth failures are unchanged directory aggregate size assertions
at indexing-options.spec.ts:95 and :121. Root Share setup and the other previously
failing file/navigation checks passed on this run.

The API evidence field `existing_go_regression_coverage` is a classification,
not an execution result. Real API/protocol scripts check audit query authorization,
event contents/redaction, protocol terminal outcomes and restore retention when
they run. They do not inject persistent audit-store failure or prove a durable
Pending interruption at runtime. Pending/Finalize atomicity, startup recovery and
write-before-audit failure closure currently have Go regression evidence only;
fixed-image fault-injection acceptance remains unexecuted.

## Formal TLS input policy and complete Lint diagnostics

A real OpenSSL counterexample showed that formal `tls_inputs` accepted a CA
missing certificate-signing Key Usage although a strict client rejected its
chain. Preparation and the existing runtime validator now both use
`openssl verify -x509_strict -purpose sslserver` with their existing CA/name
checks. The valid test fixture has explicit extensions; the nonconforming CA
is retained as a negative fixture. Client-only leaf certificates are also
rejected. All 27 lifecycle tests passed locally, including the validator's real
cryptographic command, wrong CA/DNS/IP, lifetime, encrypted/mismatched key and
existing bootstrap/secret assertions. `validate.sh` passed `bash -n` and the diff
check passed. Full POSIX/Docker validation remains subject to current-SHA CI.
Restore keeps the service stopped; the recovered certificate is checked by the
formal validate/start stage, not claimed as a cryptographic archive-format check.

The observed aa1bb690 Lint output comprised 8 errcheck, 50 govet/shadow,
1 ineffassign, 13 staticcheck and 6 unused findings across 19 files. These 78
locations are unchanged baseline statements (18 files unchanged in full; four
storage-test statements only moved after added imports). This was a source
comparison, not an independently executed baseline Lint run. **78 is the emitted
count, not a proven upper bound**: the analyzer's default per-linter cap is 50.
Both existing Lint entries now pass `--max-issues-per-linter=0
--max-same-issues=0` so the next run reports the complete finding set. Only
reporting caps change; all rules, scan scope, exit status, compatible pinned
versions and finite time budgets remain. Workflow structure and exact Makefile
command comparison passed; local Lint is unavailable because this Windows
workspace has no Go installation. No baseline code cleanup was included.
