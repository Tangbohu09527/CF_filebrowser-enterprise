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
modes, so root/Windows cannot hide a mode-zero regression. Actual rerun is pending.
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
