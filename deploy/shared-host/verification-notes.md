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
