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
