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

## Correct decimal resource authorization and stopped old-budget runs

The earlier statement that the VM runs fit an 80 GiB limit was an incorrect
interpretation of the user's 80 GB authorization. The aa1bb690 recorded sparse
virtual capacity was 84,826,357,760 bytes (79 GiB plus seed media), exceeding
80,000,000,000 bytes. Its functional prefix results remain historical evidence,
but do not establish acceptance within the authorized decimal disk budget.
No Windows VM or global system configuration was created or changed.

The still-running af65fcef shared-host run 34110905805 and queued 1e178de4 run
34111630090 were explicitly cancelled; both reached cancelled status. Their
unfinished stages must not be reported as passed. Existing completed artifacts
are retained; no live disk was resized or data reset to retry.

The next fresh VM run retains each 24 GiB system disk and reduces each isolated
data disk from 14 to 11 GiB. Including the 3 GiB base and conservative 32 MiB seed
allowance, planned capacity is 78,416,707,584 bytes. Both preflight and evidence
now enforce exact ceilings of 80,000,000,000 disk bytes and 8,000,000,000 memory
bytes; configured RAM remains 4,294,967,296 bytes. Real old-capacity rejection,
exact-byte boundaries, base/seed growth, memory units and actual QEMU argv are
covered. The existing VM harness suite passed 33 local tests after the resource
repair. These tests did not create VMs; a new real run is required.

## Uncapped 1e178de4 Lint and complete backend results

[Regular Lint job 101708974744](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34111630137/job/101708974744)
completed analysis in 53.650 seconds with all diagnostic caps removed: 113
findings across 28 files (errcheck 8, govet/shadow 85, ineffassign 1, staticcheck
13, unused 6). The extra 35 previously hidden results are all shadow findings.
Source comparison attributes 112 statements to the integration baseline and
one to this task's client-network test cleanup variable. This is not a separate
baseline Lint execution. The complete sanitized inventory is retained outside
Git; broad baseline cleanup has not been applied.

[Backend job 101708974844](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34111630137/job/101708974844)
passed the complete `go test -race -v ./... -timeout 5m` suite (HTTP 98.234
seconds). This regular workflow was unaffected by cancellation of the separate
shared-host VM workflows. Its pass does not waive the remaining Lint gate.

The cancelled af65fcef artifact was retained separately. Its last saved stage
was `idempotent-prepare-after-bootstrap`, with runtime healthy and bootstrap
absent; no `failed_api` or product failure was recorded. LAN/API/protocol/UI and
restart/restore had not begun. The initial `result: failed` field does not turn
cancellation into a reproduced application failure. The queued 1e178de4 shared
workflow produced no VM artifacts.

The single task-introduced shadow finding was corrected only by renaming the
client-network test's cleanup error variable to `serveErr`. Error assertions and
one-second socket deadlines are unchanged; diff checking passed. The remaining
112 baseline statements were not changed, and the next actual Lint run still
needs to confirm the task-specific fix.

## Bounded authorized directory totals for the two existing UI failures

The unchanged Noauth aggregate assertions are the failing reproduction for this
batch. The repair is limited to HTTP resource display, a read-only indexing
measurement adapter and a bounded fresh ACL batch. It never reuses a global
folder total as user-authorized metadata. Shared preview/WebDAV filtering and
all original resource/permission/UI assertions remain unchanged.

HTTP collects a fresh candidate tree before its existing final user/scope/path
and child-filter checks. An entire response shares 4096 entries, depth 32,
1 MiB of paths, 128-entry reads and a one-second cooperative deadline. Kernel
filesystem calls are not claimed to be forcibly interruptible. Every contribution
is checked against current scope, logical/canonical permission, file identity,
size/time and scanner exclusions; application requires a final bounded ACL/group
snapshot. Denial, change, unknown alias/hardlink accounting, read failure or
exhaustion discards the whole candidate total and preserves the existing safe
filesystem size. Thus fallback values are not complete directory-capacity reports.
Unix allocated blocks/logical bytes and the existing minimum directory sizing
are retained; regular file detail, preview and WebDAV byte lengths are unchanged.

Thirteen new test groups cover normal physical/logical trees, current and late
user/group revocation, token intersection/revocation, scope/identity/size/type
changes, excluded ancestors, sparse allocation, aliases/hardlinks and each
budget/error fallback. Existing hidden-descendant aggregate assertions are
unchanged. Diff checking and independent source review passed. This Windows
workspace has no Go/gofmt/Docker: compilation, race regression, Lint and the
original Playwright assertions must still run in CI; no runtime pass is claimed.

## 692e4010 real VM prefix and remaining source regressions

The first run with the corrected decimal resource limits completed with a
failure in [fixed-image job 101712976010](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34112904456/job/101712976010).
Its actual sparse virtual capacity was 78,383,906,816 bytes and RAM was
4,294,967,296 bytes. Both Debian 13.6 guests ran systemd, Docker 29.8.0 and
Compose 5.5.1, with independent ext4 test disks; this is mount verification,
not RAID verification. The real image build, isolated TLS registry transfer,
formal empty-root installation, administrator verification, bootstrap removal,
same-image login, idempotent preparation and actual UID/GID/tool/read-write
runtime checks passed. The builder/config Image ID was
`sha256:19793a497ae28319946895e0b1053dd399ceea808ceee4d941d3387e519cc56a`;
the registry manifest and the guests' actual containerd-store Image ID were
`sha256:0e0ffdef2238ebbe9069ea11161ffc862e4bb2100f80250f94a692b2a6ef2fae`.

The last stage was `second-vm-real-lan-and-https-boundaries`. Only a generic
client-script exit was retained, so this run cannot establish which LAN
assertion failed. It has no `lan_boundary`, `failed_api` or preview result.
API, FileBridge, WebDAV, application UI, restart and backup/restore stages did
not execute. Earlier LAN passes remain tied to their earlier SHAs and resource
limits. The next harness repair preserves failed LAN substeps as allowlisted
metadata without recording private command output or changing denial checks.

The 692e4010 regular backend job failed in three newly added token fixture
subcases before reaching their intended assertions: the ordinary test user
lacked API permission required to issue a token. The fixture now explicitly
persists that permission before issuance, and post-collection revocation tests
also require proof that collection was reached. Token capabilities, revocation
checks and expected denied responses remain. The unchanged source UI assertions
still passed Sharing 13/13 and Settings 25/25 and failed two Noauth directory
size cases (27/29 passed).

Those source trees contain two tracked same-directory symlinks. The scanner
counts the links' own Lstat bytes/allocated blocks, without traversing their
targets; the new aggregate had instead discarded the whole result at any link.
The repair uses existing no-follow entry and authenticated target resolvers,
counts only the entry, and rechecks both identities and permissions. Broken,
cyclic, directory, denied and out-of-scope aliases still discard the total.
Canonical target paths also consume the existing path-byte budget and final
ACL batch. Tests cover both size modes, a non-root user scope, replacement and
revocation, including a target outside the enumerated subtree. The test added
in this task for an allowed alias now asserts entry-only bytes rather than
fallback; its no-double-counting safety intent remains, and no baseline safety
or UI assertion changed. Scanner-default hidden-item exclusion is also retained
without changing the user's ability to list hidden items.

The uncapped 692e4010 Lint run reports 112 findings in 27 files, with no newly
introduced diagnostic: the client-network test shadow finding is gone. These
112 source statements map to the integration baseline; this was not a separate
baseline Lint execution. Broad baseline cleanup remains outside this batch.

## Actual unsupported-preview red test and minimal error classification

Test-only SHA `364571a4242e06dc0f36815f33a797cd66978b30` reproduced the issue in
[backend job 101716903338](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34114138736/job/101716903338):
`TestAuthenticatedPreviewWithoutServerPreviewReturnsBadRequest` received HTTP
500, zero body bytes and `this item does not have a preview`. The ordinary user
had Browse and Preview, no Download or Admin; the real handler ran. That job
also had the separately identified aggregate token fixture failures.

Only the two authenticated unsupported-preview errors now wrap the existing
`ErrInvalidRequestParams` sentinel. The shared-preview branch, general status
mapper, access-denied handling, bad-image errors and security timeouts are
unchanged. The existing 403 and genuine 500 security assertions remain. The
acceptance client still rejects unexpected 500 responses; it is not relaxed to
label them as unsupported previews. The new green result and all affected Go,
original Playwright and fixed-image checks must come from the next real CI run.

The LAN diagnostic regression first failed against the old reporting path
(2 failures and 4 errors); a separate missing-observation success case also
failed before its guard was added. The repaired existing VM harness test file
passed 41/41 tests locally, including real strict-certificate loopback tests.
These are harness/crypto tests, not application LAN acceptance. Generated guest
Shell/Python syntax, the existing shell entry and diff checks also passed.
Success now requires every original LAN control and its validated observation;
failures retain only fixed stages, completed checks, bounded numeric codes and
allowlisted categories. No API, authentication, network or process deadline was
relaxed. The actual 692e4010 LAN cause remains unclassified until a new run.

Independent review additionally required failed reports to retain only the
ordered completed prefix before the current stage, and to discard observations
from future stages. The corresponding new prefix cases failed before the fix.
The existing millisecond representation already used integer truncation; new
4.9996-second and 5.0000-second cases confirm the unchanged real five-second
boundary, not a timeout relaxation or a second reproduced timing bug.
After this refinement, the actual local command
`python.exe -B -m unittest -v deploy.tests.test_shared_host_vm` passed 44/44
using Python 3.12.10 and the existing OpenSSL 3.5.6. Shell syntax and diff checks
passed. The intermediate test-only shared workflow 34114138692 was cancelled
after its regular workflow produced the preview red test; its unfinished VM
steps are not passes. The subsequent complete head workflow remains required.

## a276d255 backend pass, source-copy race investigation and formatter evidence

Both the 890a351e and a276d255 complete regular backend race suites passed.
The 890a351e HTTP package took 86.556 seconds; new directory/preview checks and
original bad-image/oversized-image 500 and permission-revocation 403 regressions
passed. The 890a351e source workflow passed Sharing 13/13, Settings 25/25 and
Noauth 28/29. Both original indexing-size UI cases passed. The remaining copy
case reached its final error check after both PATCH payload/result and visible
file assertions succeeded, then reported two browser NetworkErrors. Its retries
encountered data left by that first attempt. No data was cleared to hide this.

The old log lacks the failed request URLs, so navigation cancelling an in-flight
refresh is an inference from the application and test sequence, not a proven
historical transport cause. Copy starts a directory refresh before displaying
its success notification; the test immediately performed a full navigation.
The existing copy helper now tracks only current-directory GET requests started
after its copy PATCH, verifies the refresh's 200 status and completed body, then
continues the original notification/navigation/assertions. It also reports at
most eight failed requests as fixed endpoint/method/error categories, without
URLs, query strings, headers or bodies. The original five-second response wait,
retry policy and zero-error assertions remain. Node syntax and diff checks
passed; the existing Playwright entry must provide the runtime result.

a276d255 frontend unit tests passed 115/115 across 17 files, with frontend Lint,
translations and generated-doc checks passing. Its Lint remained the identical
112 findings in 27 baseline files, with no added/removed diagnostic. The
analyzer took 43.558 seconds with the pinned Go 1.26.8 / golangci-lint 2.12.2.
The existing format job reports success after `go fmt ./...`, but that command
rewrote 19 CI-workspace files, including two aggregate files from this task.
It has no cleanliness gate, so success is not proof of clean source formatting.
Temporary read-only diff output after the unchanged full formatter command
will retrieve those two official Go 1.26.8 formatting patches. The other 17
files will not be reformatted in this worktree as incidental cleanup.

The temporary formatter diagnostics ran in regular workflow 34116707213,
format job 101725110964, using Go 1.26.8 linux/amd64. Its official patch changed
only two field alignments in `resource_aggregate.go` and expanded one test
function literal in `resource_aggregate_test.go` (+5/-3). The patch passed
`git apply --check` and was applied only to those two task files. Temporary
CI diff output was then removed, preserving the original full `go fmt ./...`
entry. Formatting changes to the other 17 files were not applied. Sixteen
whole-file blobs still match the integration baseline; the seventeenth is
`backend/swagger/docs/docs.go`, updated by this task through the existing
generator. A successful formatter command alone is not proof of clean source.


## a276d255 real LAN/API progress and cf1b6bc9 source checks

[Fixed-image job 101723135170](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34115475187/job/101723135170)
ran source `a276d255e2887e80e6667f90a588669d9dbf4f18` on two Debian 13.6
systemd guests with Docker 29.8.0 and Compose 5.5.1. The actual virtual disk
total was 78,383,906,816 bytes and configured RAM 4,294,967,296 bytes, within
the authorized decimal limits. Each business disk was independently mounted
ext4; this is mount evidence, not RAID validation. The registry manifest and
both guests' actual Image ID were
`sha256:926982f27ce87063e57ce1de2be929617685592f3deff92d3d3eca5debe10b37`;
the builder/config ID was
`sha256:0d0d2d655c0414e67c80b4f82a807aaf8da0637bde1fb01497c0412049f1b32d`.
Source/config/layer identity matched across the isolated registry transfer.

Formal empty-root prepare, administrator verification, bootstrap removal,
same-image login, idempotent prepare and the actual UID/GID/directory/tool
checks passed. All eight LAN subchecks passed: allowed-source UI and health
returned the expected HTTP 200 bodies before/after the controls; the denied
source really connected over TCP with the expected source and peer, then
received TLS EOF after 23 ms, no completed handshake and zero application
bytes. The untrusted CA control returned curl 60. No certificate or peer
verification was bypassed. This result does not identify the earlier
692e4010 run's unclassified failure cause.

The initial API exercise passed its 226 assertions over 167 requests, including
file byte round trips, ordinary-user and Token permission boundaries, Share
password states, archive rejection and audit queries. These are the executed
assertions, not a claim that every requested acceptance category is complete.
The preview reporter observed image responses; TXT and XLSX had the same
response digest, so their content parsing is not established by that result.
Preview content and the real viewer route are being checked separately.
Persistent-store failure injection and Pending interruption remain unexecuted
in this fixed image; existing Go regressions are separate evidence.

The run stopped at `real-filebridge-and-webdav-protocols`, on
`filebridge_list_uploaded_entry`: 55 preceding protocol assertions passed,
with 13 HTTP requests and 11 real FileBridge binary invocations. Its compiled
client SHA-256 was
`6d5ac02cfd4e5e5347f905583139f62119899f4931f9ac8638ad84333b3619dd`,
using the guest's Go 1.25.0. WebDAV's remaining protocol checks, fixed-image
Playwright, container/daemon/host reboots and blank recovery were not reached.
The sanitized `vm-result.json` and non-secret image input artifacts retain the
precise failed check. No private protocol output, backup or VM disk is uploaded.

At source `cf1b6bc92f942a89e6aa9e88de94c057370f0f0b`, regular backend job
101726395679 passed `go test -race -v ./... -timeout 5m` with no failures.
Three existing Windows-only cases and one case-insensitive-filesystem alias
case were not executed on Linux; their conditions and assertions are unchanged.
Frontend units passed 115/115 in 17 files. Deployment job 101726395466 passed
`make validate-deployment` (25 and 153 tests in its two suites). Each of the
22 tracked Shell files also passed a separate local `bash -n` at this SHA.
These static and source checks do not replace the pending complete VM run.

The cf1b6bc9 formatter no longer rewrote the two task aggregate files; it still
reported the other 17 files described above. Full Lint still failed with the
same 112 findings in 27 files, using Go 1.26.8 / golangci-lint 2.12.2. No finding
was added or removed relative to the preceding uncapped inventory. Broader
source cleanup is awaiting the explicitly requested scope decision; tests,
rules, scan scope and failure exits remain enabled.


## Documented stage failure closure and FileBridge list-size regression

The README's dependency blocks already used child Bash with `set -euo pipefail`,
but later naked command blocks did not inherit those options. In particular, a
failed backup command could still reach the following start. The optional
publish example was also the only earlier Image ID assignment, and the second
host's image reference was used before assignment. The added executable README
control-flow tests reproduced 11 failing subcases before the documentation fix.
Each documented stage now has its own bounded Bash block and explicit inventory
inputs. Prepare, backup and restore inspect the image on the current host in
that stage; no optional publication or inherited shell variable is required.
These tests replace sudo with a synthetic stub and are not Docker acceptance.

The real a276d255 FileBridge failure was a test contract mismatch: the controlled
47-byte regular file had already passed actual client read and SHA-256 checks.
The directory display uses 4 KiB rounding when the source's existing
`useLogicalSize` setting is false, so its correct listed size is 4096. The old
helper incorrectly required 47. A direct check against that old function
reproduced the rejection, and new mode tests failed before the helper repair.
The helper now reads the unique source's explicit boolean setting through the
existing settings API and requires the exact existing display calculation.
Missing/wrong entries, source/path/name/type, invalid size or ambiguous settings
still fail. Actual read/checksum/download assertions continue to require all
original bytes. Product and FileBridge CLI behavior are unchanged.

The two affected existing files passed together locally:
`python.exe -B -m unittest -v deploy.tests.test_shared_host_lifecycle deploy.tests.test_shared_host_protocols`
reported 49/49 tests passing in 2.556 seconds. This includes real strict OpenSSL
certificate checks, documented inner Bash syntax, failure-before-start cases,
current-host image derivation and logical/physical display boundaries for empty,
aligned and cross-block controlled files. `git diff --check` also passed.
The next actual fixed-image run must confirm the FileBridge correction and
execute all remaining WebDAV/UI/reboot/recovery stages.


## Converted-document viewer red test and retained original UI failures

Test-only source `ac9f7a5b3154ce3e5ded83293687a0fa8decfc3c` failed exactly
six frontend unit cases in [job 101732785667](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34119115863/job/101732785667):
XLSX, PPTX and SVG, in authenticated and shared contexts, requested `original`
instead of a derived image. The real Preview component's computed URL was
executed; its surrounding store/API dependencies were mocked. The other 131
unit cases passed, including 16 original-download and HEIC/raw/Safari contract
controls in the new file. This is a reproduced URL selection failure, not a
claim that six real document renderers were exercised by those unit tests.

The repair changes only the converted-document branch to the existing `xlarge`
preview. Original-file download, inline PDF/TXT/image reads, HEIC/raw selection,
backend `original` behavior and all authorization/error assertions are retained.
The existing shared-host Playwright project now opens two distinct synthetic
XLSX files through that actual viewer, requires a successful full-image xlarge
response and decoded nonwhite pixels, and rejects identical raster digests.
Its evidence contains only dimensions, nonwhite-pixel counts and pixel hashes.
The original workbook bytes are unchanged; the alternate workbook is uploaded
through the normal API and included in the existing stored-file and restore
hash checks. This tests content-sensitive raster preview, not OnlyOffice or
semantic spreadsheet interpretation. It still requires an actual VM run.

The API probe now describes successful image MIME/bytes as `image_response`
and explicitly records that it did not validate decoded content. Its requests
use xlarge, matching the document viewer. The old small thumbnail path crops
to fill, which could explain matching short-document white thumbnails; no
original JPEG pixels were retained from the historical run, so that explanation
remains an inference, not a proven renderer failure or icon fallback.

[cf1b6bc9 source job 101729409747](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34117109983/job/101729409747)
passed Sharing 13/13, Settings 25/25 and Noauth 29/29, including the copy refresh
repair. General then passed 21 and failed two cases. Its copy test expected a
trailing slash in the selected directory label, while the component and actual
response displayed `/myfolder`; only that exact label expectation is corrected,
retaining both real copies and all notification/result/error checks. The
duplicate-finder case received HTTP 200 but did not display its two expected
entries. It remains under investigation without changing its locator, timeout,
fixture sizes or safety requirements. Later source suites were not executed.


The UI evidence reader additionally requires exactly the five existing case
IDs, finite retry/status values, successful final case outcomes, a zero process
exit and valid distinct nonblank rasters. Failures retain only those safe case
states and bounded raster values; raw guest/browser output stays private. Its
new rejection tests failed before implementation; the complete existing VM
harness file then passed 52/52 local tests, retaining all original 44 tests.
This is reporter validation, not real application UI acceptance. Python/API
regression, TypeScript syntax and fixture XML/CRC checks also passed locally.

The later cf1b6bc9 fixed-image run repeated the complete LAN and initial API
prefix with the same original FileBridge list assertion failure. Its guest
Image ID was
`sha256:bfb0e960bd0f7c5b5b8e6c3f4ac5ce505e9294f98f608750059537e31e053169`.
Disk/RAM usage remained 78,383,906,816 / 4,294,967,296 bytes. No UI, reboot or
restore pass is inferred from that prefix. The already committed FileBridge
helper correction is being exercised by a later fixed-image run.


## 89c27efe confirmed source regressions and preview unit pass

At source `89c27efee4180ff0d40fb931509e6dd0d069d320`, frontend job
101738488034 passed all 137 tests in 18 files, including 22/22 preview URL
cases. This confirms the minimal URL repair; real fixed-image rendering still
requires the pending VM UI stage.

[Backend job 101738488422](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34120918917/job/101738488422)
ran the unchanged complete race command with Go 1.26.8 linux/amd64. The new
real-index duplicate test recorded two real files, each 1,153,024 logical bytes
and 1,155,072 scanner-allocated bytes. Synchronous indexing yielded the two
expected SQL candidates; the actual ordinary-user handler returned 200 but no
group in physical-size mode. The logical-size subcase passed. The failure at
the group assertion reproduces the real size-contract defect, rather than an
index setup or permission failure. Existing duplicate ACL and secure-open
file/scope-root replacement regressions passed. The HTTP package failed after
106.903 seconds; this head is not a backend pass.

Deployment job 101738487818 also reproduced both new restore-parent rejection
failures among 170 tests: storage parent 0777 and configuration parent 0775
passed the old production guard and reached the test's lock sentinel. The
protected 0755 parent control passed. These tests use real temporary layout,
archive and guard code with modeled POSIX ownership/modes and isolated host
checks; they are not proof of a real Linux mount or completed recovery.

The restore repair adds only a check for the nearest existing parent's own
group/other write bits after its existing path/owner checks. The existing loop
already covers configuration, data, cache and storage roots. Unsafe parents
are rejected before locking or archive work; no ownership or permission is
automatically changed. After repair, the existing backup tests passed 20/20
and restore-evidence tests 10/10 locally. The next CI and real blank-VM restore
remain required.


## Duplicate size repair awaiting complete CI

The reproduced duplicate failure is repaired at the existing authenticated
checksum resolver. Its already-authorized file stat is compared with the
scanner size using the source's existing logical/allocated mode; Unix uses
stat block allocation and Windows retains the scanner's 4 KiB rounding.
Invalid, missing and overflowing metadata are rejected. The SQL bucket and
public response size are unchanged. Logical byte length is included in both
header and middle checksum identities and therefore in the final merge key.

The real-index regression now also rewrites one fixture with one additional
byte, verifies that both real SQL candidates remain in the same physical-size
bucket, and requires no duplicate group. Missing/negative/unknown/overflowing
stat metadata has explicit rejection tests. Existing permission, Token,
canonical-path and secure-open checks still execute before reads/cache reuse.
This does not turn the existing sampled MD5 algorithm into a full-file equality
check or solve its existing read-after-stat concurrency/cache limitations.

Read-only peer review and `git diff --check` passed. Go compilation and the
complete race regression after this repair are still pending in the existing
CI because this Windows workspace has no Go toolchain. The preceding red test
is preserved above. The protected-parent backup repair was independently
rerun locally: 20 backup tests and 10 restore-evidence tests passed. These local
checks do not establish a successful actual blank-VM recovery.


## e5deaed7 complete backend and deployment checks

Source `e5deaed7a1a37d78051434953acb9e8e9617512f` passed the actual complete
`go test -race -v ./... -timeout 5m` command in [backend job
101743498489](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34122486563/job/101743498489)
with Go 1.26.8 linux/amd64. The HTTP package completed in 108.335 seconds.
Both real-index logical/physical size cases passed, including the same SQL
physical bucket with two different logical lengths returning no duplicate.
Invalid-stat and retained ACL/secure-open/identity/cache/alias checks passed.
The Windows-specific allocation rounding branch was not executed on Linux.

[Deployment job 101743497377](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34122486488/job/101743497377)
passed the existing `make validate-deployment` entry point: 25 and 170 tests,
including unsafe-parent rejection and the protected-parent control, followed by
the retained configuration, systemd, Dockerfile and clean-worktree checks.
These results repair the prior two red regressions. They do not establish a
successful full Lint run or actual blank-environment recovery.

## ac9f7a5b actual FileBridge and WebDAV pass; UI still failed

The completed [fixed-image job
101735729918](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34119115840/job/101735729918)
used source `ac9f7a5b3154ce3e5ded83293687a0fa8decfc3c`. Both Debian 13.6/systemd
guests used Docker 29.8.0 and Compose 5.5.1; total virtual disk and RAM were
78,383,906,816 and 4,294,967,296 bytes. Its registry/guest Image ID was
`sha256:16182283f3d865533b0d6c313e8d85e3397e758c462a43a25401b3256eec6229`;
the builder/configuration ID was
`sha256:7fb87e18bf4153185f6e7a8004eb5d0cc6b9e1e824c7814f6bdd9fa63dce23d2`.

All eight actual second-VM LAN checks passed (denied-source TLS EOF after 19 ms,
zero application bytes, wrong CA curl 60). Initial API acceptance passed 226
checks over 167 requests. The real protocol phase then passed all 235 checks
over 80 HTTP requests and 33 actual FileBridge binary calls. It verified the
repaired list display size while retaining byte-exact upload/read/download,
trusted HTTPS, least privileges, Token intersections/revocation, source/root/
traversal/dangerous-command refusal and local audit redaction. The real WebDAV
client exercised PROPFIND, MKCOL, PUT, GET/HEAD/Range, COPY/MOVE/DELETE, scoped
hrefs, ordinary-user Create/Modify/Download/Delete restrictions, Token
intersections/revocation and destination boundary rejection.

The first failure was `initial-existing-playwright-ui`: the ordinary management
user's existing `npx playwright test --project shared-host` exited 1. Node/npm,
Chromium dependencies and NSS CA trust setup had completed. This older head did
not yet retain per-case or raster diagnostics, so the specific browser failure
is unknown; it is not attributed to the later XLSX repair. No private browser
logs were fetched. Only the permitted VM result and build-input artifacts were
retrieved. UI, container/daemon/host restart and blank restore did not pass or
complete in this run. This protocol client evidence does not certify a real
OnlyOffice Document Server, Hermes or WeChat integration.


The e5deaed7 regular frontend job 101743498431 also passed 137 tests in 18
files (Vitest 4.1.8, 12.64 seconds) using the existing `npm i && npm run test`
command. The retained full Lint job 101743498488 still failed: 112 findings
across 27 files (errcheck 8, govet 84, ineffassign 1, staticcheck 13, unused 6).
No new duplicate implementation/helper/test diagnostic was introduced. Compared
with cf1b6bc9, 111 diagnostics match exactly; the remaining unchanged-file
finding at `http/audit_token_test.go:320:17` still concerns a redundant explicit
`*users.User` type but was reported as QF1011 instead of ST1023. This is not a
claim that all diagnostic text is identical or an explanation of analyzer
selection. The broader source cleanup scope remains unresolved; no rules,
checks or assertions were disabled to obtain a green result.


## e5deaed7 existing source UI advances to proxy setup

[Source regression job 101744099651](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34122486557/job/101744099651)
passed frontend types/lint/unit/build and the independent FileBridge tests,
then ran the unchanged full `make test-playwright` entry point. Sharing passed
13/13 (36.2 s), Settings 25/25 (52.7 s), Noauth 29/29 (1.1 min), and General
23/23 (57.6 s). The latter now includes the actual duplicate/context-menu and
copy-label regressions. JWT passed its four applicable cases (16.5 s); its 12
existing project-mismatch skips remain visible and were not added by this task.

The next proxy image failed at `Dockerfile.playwright-proxy:15`, specifically
the existing `proxy-setup.ts:16` page-title assertion after 5 seconds. The title
was the allowlisted `Graham's Filebrowser - Files`, while the test expected an
additional proxy username suffix. This is still being investigated; no title,
authentication or sharing assertion was removed. The previews, OIDC, no-config
and screenshot images after proxy were not executed in this run. This source
UI run is separate from the real fixed-image VM UI failure on ac9f7a5b.


CI checkout provenance was checked separately: regular backend/frontend jobs
101743498489 / 101743498431 used GitHub's PR merge checkout
`0f740b270a7e8187b8748b207d8ef3d7b243fc37`, while shared-host source job
101744099651 checked out the explicit head `e5deaed7a1a37d78051434953acb9e8e9617512f`.
The GitHub commit API confirms their tracked tree SHA is identical:
`b3db392a0f962c19ff02a32ca6c7f491cdd561cd`. Thus the regular results apply to the same
tracked content, with the actual merge commit distinguished from the PR head.
The fixed-source build/VM workflow explicitly checks out the head SHA.


## Bounded Pending interruption and failure diagnostics, awaiting a real VM run

The existing VM/API harness now prepares a dedicated synthetic directory and
ordinary scoped user before the main acceptance seed. It sends 64 KiB of a
finite 1 MiB PUT, holds the trusted TLS connection with a 120-second bound,
and observes only a stable, matching new temporary prefix while the original
file is unchanged. Only then may it kill the uniquely verified project/service
container. Its image, identity, stopped state and both unrelated sentinels are
checked. The formal start entry must restart the same image/container; the
real audit API must then return the single `unknown/process_interrupted` event,
match its exact request ID, preserve the original bytes and allow a subsequent
ordinary write/read. Failure preserves the scene; fixed operation labels and
strictly allowlisted API check/status/count evidence identify the failing stage.

Two review-time harness defects were reproduced before repair. A fixture read
from the real Compose YAML rejected the old hardcoded service label; the guard
now matches `filebrowser-enterprise`, retaining wrong-service/container/image
rejection. A real Client.request URL test, checked against the backend query
allowlist, rejected the old `requestId` parameter; the query now uses `requestID`
while the returned DTO still uses `requestId`. This avoids a mock-only apparent
pass followed by a real API 400. No product contract or assertion changed.

The existing shared-host UI case summary now additionally retains only the
last entered operation from a fixed enum. A failed/unknown stage cannot become
a pass; passed cases require their final operation. Original CRUD/preview/
logout assertions and timeouts remain. For the existing proxy setup failure,
the original title assertion runs first with its original deadline. Only on
failure do two bounded same-browser probes check actual identity, permissions,
source scope and directory metadata using fixed booleans/statuses. Even if
those probes pass, the original title error is rethrown. Credentials, raw API
bodies, browser errors and URLs are not copied into diagnostics.

Executed locally after integration: `python -B -m unittest
 deploy.tests.test_shared_host_audit_pending deploy.tests.test_shared_host_vm
 deploy.tests.test_shared_host_protocols` passed 92 tests (19 + 56 + 17).
Both modified existing Playwright files passed Node 22.23.1 strip-types syntax
checks; Python compilation and `git diff --check` also passed. These are harness
regressions, not actual Docker/browser/Pending acceptance. The running e5deaed7
VM has none of these new Pending/operation diagnostics. Actual Store EIO
injection is separate, remains unexecuted, and is not implied by Pending recovery.


## e5deaed7 real VM narrows the remaining browser failures

[Real VM job 101744099980](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34122486557/job/101744099980)
completed with failure at `initial-existing-playwright-ui`. The public case
summary records CRUD and XLSX as failed, and PNG, JPEG and logout as passed,
all on retry 0. The process exited 1; no acceptable XLSX raster summary was
produced. This head did not retain the last entered operation, so the failing
CRUD step and XLSX cause remain unknown. Storage/API success is not preview
success, and no private browser artifact was retrieved to guess the cause.

Before the browser failure, the fixed-source real-image install, bootstrap
removal and same-image login, actual service UID/GID and protected mounts,
second-VM verified HTTPS/actual denied TCP peer checks passed. The initial API
ran 169 requests and 229 checks successfully; the actual FileBridge/WebDAV
phase ran 80 HTTP requests and 236 checks, including 33 FileBridge executable
invocations, successfully. These results are specific to source
`e5deaed7a1a37d78051434953acb9e8e9617512f`; they do not certify the later Pending
or Store EIO harness. Container/daemon/host reboot and blank restore were not
reached after the browser failure and remain unverified.

Both Debian 13.6 systemd guests used the registry manifest/actual guest Image ID
`sha256:1aa8e0dad658c194bd5de0519196a7d9ddc879fd2c3a40b56b1e2322d01d92de`;
the builder Image ID/config digest was
`sha256:f5275a41d21ec38f18bc3f6b0f942f827dcbff20fc5e425775290e23f4308ecc`.
The two guests used 4,294,967,296 bytes of configured RAM and
78,383,906,816 bytes of total sparse virtual disk capacity, within the explicit
decimal limits. Independent ext4 test disks validate mounting, not RAID.


## 49ea34bc ordinary regressions and source setup failure

The regular backend job 101754209194 passed the retained `go test -race -v
./... -timeout 5m` command (HTTP package 105.039 s). Frontend job 101754209274
passed all 137 unit tests. The complete Lint job 101754209261 still reported
112 findings across 27 files; an initial narrow log parser matched none,
then the complete position/rule extraction matched all 112 with no unknown
position lines. An empty parser result is not a clean Lint result.

[Source job 101755076863](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34125846128/job/101755076863)
passed frontend types/lint/unit/build and the independent FileBridge checks.
The unchanged full Playwright entry stopped in the sharing setup at
`global-setup.ts:116`: the enabled Create checkbox remained unchecked after
its visible slider was clicked. The previous e5deaed7 run passed this setup;
a cause has not been established. Proxy setup and its newly added diagnostics
were not reached. An attempt to rerun only this source job was rejected by
GitHub with HTTP 403 because its original workflow was still running; no
rerun or extra VM was started. The original failure remains recorded.

## Real Audit Store write-failure probe, implementation awaits execution

The existing VM flow now also invokes a separate disposable-guest-only probe
after Pending recovery. An ordinary scoped user's saved session first writes
and verifies a different payload, verifies the terminal audit record, and
restores the original payload. The observer verifies writes to the real
FileBrowser Bolt database descriptor. A second finite window injects EIO into
that descriptor's `pwrite64` calls while exactly one valid ordinary-session PUT
is attempted. It requires the exact HTTP 503 audit-unavailable response,
unchanged target bytes/inode and no remaining temporary file, then detaches.
The formal stop/start entry must retain the same container and image while
starting a new process. The same saved session must read the original bytes,
retain prior terminal audit records, find no recovered event for the failed
request ID, and successfully perform and audit the same write afterward.

The pinned Debian strace 6.13 runs only in the already authorized disposable
VM. [Its documented thread/descriptor controls](https://manpages.debian.org/trixie/strace/strace.1.en.html)
are combined with local-daemon/container/image, executable, UID, namespace,
DB inode/FD and per-record thread-membership checks. The main window is 60 s
with an independent 70 s watchdog; exact process descriptors bound termination
and every completed window independently verifies all service threads detached.
Guest SSH/report/join bounds remain finite. Raw syscall arguments remain in an
anonymous pipe and are never saved; public evidence contains only fixed stages,
booleans and bounded counts. No host kernel, Docker capability, product timeout,
Windows setting or public registry is changed.

The database also receives scanner writes, so an EIO count alone is not an
audit failure proof. The positive controls, exact response and existing
write-before-file-open ordering support attribution. FD/thread checks are
samples, not proof against transient descriptor reuse; before/after temporary
file checks prove no residue, not that a temporary file never existed. These
limits remain explicit. Failure preserves data, joins the bounded worker,
checks detachment where reachable, and stops subsequent windows/restart.

Local implementation regressions passed: VM orchestration/collector 64 tests
and Audit helper tests 40 (21 Store EIO + 19 Pending), 104 total. AST/whitespace,
Node strip-types syntax and `git diff --check` passed. The existing browser
case recorder now identifies fixed workbook 1/2 response/viewer/decode stages
and editor save stages, keeping every original interaction, timeout and
assertion. All of these are implementation checks; actual Store EIO, syscall
coverage and the revised browser diagnostics have not yet run in a VM.


## Reject incompatible image revisions before creating restore targets

A local regression through the formal restore CLI reproduced a preflight gap:
with matching archive/source fields and local Image ID, a different or missing
OCI image revision label was not rejected and the temporary restore layout was
created. The normal prepare/validate entry already enforces this label contract;
this does not mean a normal compatible backup was observed failing in a VM.
The restore preflight now applies that same source-revision requirement before
creating configuration, data, cache or business-storage directories. A further
Docker-style `Labels: null` negative case first reproduced an AttributeError;
the guard now treats it as missing and returns the defined BackupError.

The existing backup test module passed all 21 tests after the minimal repair.
The new CLI negative cases cover different/missing/null revision and the
retained different-Image-ID refusal, checking every target remains absent and
both archive bytes and unrelated sentinel remain unchanged. The compatible
positive CLI case now also traverses the real version-check function. Host,
source and Docker reads are simulated; no real restore pass is claimed here.
Only backup.py and its existing test module were changed for this issue.

The preceding cf8c23f3 deployment CI job 101760200165 passed the existing
`make validate-deployment` entry with 25 tests (0.064 s) and 222 shared-host
tests (12.616 s). That run predates this restore revision repair. The new
Pending/EIO probe still awaits its real VM execution; unit/deployment CI
success does not establish Audit syscall fault or blank restore acceptance.


## 49ea34bc real Pending recovery passes; editor failure is earlier than save

[Real VM job 101755076733](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34125846128/job/101755076733)
completed with failure at the original initial UI stage. All 19 public Pending
orchestration checks passed: observed persisted partial-upload bytes, exact
service/container interruption, client disconnect, same-image formal restart,
recovered terminal event and exact request-ID lookup, unchanged original file,
subsequent real write/read, and unchanged unrelated sentinels before/after.
The controlled audit interruption proves that specific restart/recovery path;
it does not complete normal container/daemon/host reboot acceptance.

The source was `49ea34bcae2ee568d81b01813fd26e106b98fcb8`. The guest Image ID /
registry manifest was
`sha256:7119a35e8a57bd4a8ed2bba23f6c00d55419d2c28df7658fdcb6a0558ac2ac46`;
the builder/config identity was
`sha256:4659a235b5e876f865927326ae27614bfab3033bae2b7dfb23b12ed7d3b5ba1e`.
API 169 requests/229 checks and FileBridge/WebDAV 80 HTTP requests/236 checks,
including 33 real FileBridge invocations, passed. The two guests stayed within
4,294,967,296 RAM bytes and 78,383,906,816 sparse disk-capacity bytes.

CRUD failed after entering `edit`: upload had reached its visible listing
assertion, but save had not been entered. This rules out attributing this run
to a save/navigation race. It does not identify which editor interaction failed.
XLSX failed with no acceptable raster summary; PNG, JPEG and logout passed.
The later fine XLSX stages and real Store EIO probe were absent from this head.
Normal lifecycle, backup and blank recovery were not reached. Four new fixed
editor stages now separate opening, rendering, focusing and replacement while
keeping original interactions, assertions and deadlines.

## b35e1588: regular/deployment passes, upstream pull and source UI fail

Regular backend job 101763571240 passed the full race command (HTTP 102.919 s),
and frontend job 101763571063 passed all 137 unit tests. Deployment job
101763571275 passed the existing entry with 25 tests (0.039 s) and 223
shared-host tests (10.974 s), including the restore revision guard. These jobs
checked out PR merge `7eeaaef4a7a1fa57f821910f1cb87c5830f39426`; the GitHub
commit API confirms its tree equals head
`b35e15885d8083d3fc35bb1999ddb8b488a8476f`:
`568c520ff22bbcbc9c945fa05260cad4d1874e12`.

Lint job 101763571384 still reported 112 findings across 27 files. Read-only
source mapping found 26 file blobs unchanged from the handoff baseline; the
four reported lines in the remaining storage test file exist unchanged at
shifted line numbers. All 112 reported source lines are present in the baseline.
This is a source comparison, not a new execution of baseline Lint, and does not
turn the failing required check green.

[Fixed-image job 101766997278](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34128764701/job/101766997278)
failed at the first `gtstef/ffmpeg:8.1-decode` pull with HTTP 502 Bad Gateway
and exit 1. No fixed application image or VM artifact was produced; the VM
step did not run. It supplies no installation, EIO or restore result and is
not a source/image-identity guard failure.

[Source job 101766997523](https://github.com/Tangbohu09527/CF_filebrowser-enterprise/actions/runs/34128764701/job/101766997523)
passed frontend/FileBridge prerequisites and progressed beyond sharing setup.
Its unique failing spec was `2x copy from listing to new folder`. Parsing the
attempts separately corrected the initial combined diagnosis: attempt 0 reached
the final `checkForErrors` at `general/file-actions.spec.ts:113`, after both
copy-success notifications and the final directory-title assertion. It failed
because the existing console-error check expected 0 and received 1, classified
as NetworkError. Only retries 1 and 2 failed at the first notification wait
(:82), with no notification/toast. Those later failures do not establish the
first attempt's cause. The prior Create checkbox failure was not reproduced.
The network error remains under investigation; proxy completion is not inferred
from absent diagnostic labels. Raw error bodies, URLs, credentials and private
browser artifacts were not retained in public evidence.


## Preserve a failed UI disk snapshot before independent lifecycle checks

The real UI runner still executes the same five cases once, with every original
assertion and timeout. Only a complete, strictly validated set of case failures
with process exit 1 can enter a continuation path. Missing/unknown stages,
interruption/skips, inconsistent results, missing raster proof for a supposedly
passed XLSX case, or dispatch/setup/evidence failures stop the run. A review
counterexample initially admitted unknown-stage reports; the narrow admission
guard now rejects them while the general collector retains their failure
information.

For an eligible initial UI failure, the original failure remains recorded.
The formal stopped-backup entry creates a new private 0600 archive containing
business files, database/audit, configuration and keys; no existing package is
overwritten. Its protected regular inode, size and digest are checked before
the same container/image is formally started. Both sentinels must be unchanged.
The client UI output and archive remain private for the runner lifetime; only
bounded metadata is published. This preserves disk data, not process memory.
No UI retry or database cleanup is introduced.

The original container/daemon/host reboot, missing/late storage and blank-restore
checks then continue independently. A failed backup, identity, health, isolation
or later stage still stops execution. Even if subsequent restored UI succeeds,
the initial UI failure is retained and the final runner returns exit 1 instead
of reporting full acceptance. Existing VM/Pending/EIO regressions passed
114/114 after red-to-green admission and final-exit tests; this is not a real
failure-snapshot or lifecycle/restore pass. The new editor stages passed Node
syntax checking, with unchanged controls and content/hash assertions.


## 6610366d regression and bounded failed-fetch diagnostics

At source `6610366dcf6d86a4332b3b074b290fc7d2ee4610`, regular backend
job 101772276479 passed the full race suite (HTTP 102.644 s), frontend job
101772276245 passed 18 files / 137 tests, and deployment job 101772275841
passed the existing entry with 25 + 233 tests. These regular/deployment jobs
used PR merge `d43402b9e1650933e5052c7580e885c3fcac20c4`; GitHub metadata verifies the
same tree as the source head: `782d01b17794de08910b9c8d6542e363b8558457`.
Full Lint remains failed with 112 findings / 27 files / 5 rules. The required
check remains enabled; source mapping to baseline does not mean Lint passed.

The existing Playwright error-tracking fixture now records at most 16 failed
fetch categories and a truncation flag, only when its original console/API
error-count check fails. Output contains fixed endpoint/method/resource/error
categories and a navigation boolean. Request URLs, queries, headers, bodies
and arbitrary failure text are not retained by this new collector. Original
console/API collection and assertions are unchanged; no failure category is
ignored and no timing budget or retry count is changed. The added listener is
removed when the fixture exits.

This addresses the missing diagnostic information in b35e1588's initial copy
attempt, not an established product defect: its original fixed Firefox
NetworkError has no identified endpoint or status. Node syntax and an in-memory
call of the real tracking function checked sensitive URL inputs, unknown values,
the 16-record bound, silence on expected counts, continued assertion failure
and listener disposal. These checks do not constitute a browser regression;
the new diagnostics still require execution through the existing UI entry.


The current source UI job 101772276349 also reproduced the copy failure:
attempt 0 reached the final check with exactly one fixed Firefox NetworkError;
both copy notifications and the final title had passed. Retries 1 and 2 failed
at the first notification. There was no failed-HTTP-response block identifying
an endpoint or status. This run predates the new failed-fetch collector.


## Fragmented trace reads retain finite parsing limits

A local counterexample reproduced a false failure in the EIO probe parser:
1,600 identical valid raw pwrite records passed with 4,096-byte reads but failed
when one byte was followed by a 65,536-byte read. The old check applied the
read-size bound to that new block plus the previous partial line. This has not
been observed as the cause of any real VM result.

The parser now limits each input block to 65,536 bytes, parses complete lines,
and retains the existing 4,096-byte complete-line/residual limit and 10,000
completed-write limit. Temporary combined storage is bounded by 65,536 + 4,096
bytes. A new cumulative raw-input limit of 81,940,000 bytes rejects additional
input before buffering; this was not an existing cumulative limit. Unknown
trace forms, wrong descriptors/threads and unmarked EIO remain refused. The
fragmented-stream red-to-green case and all boundary counterexamples passed;
the existing VM/Pending/EIO modules passed 117/117 tests locally (1.077 s).
This changes only the test probe and its existing tests, not product I/O,
authentication, Audit ordering or timeout contracts. Real strace/VM acceptance
remains separate from these local parser checks.
