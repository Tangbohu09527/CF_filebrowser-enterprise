# Scoped product ZIP workflows

This candidate builds on FileBridge `8d12d21e` / product `f3a63895e33958dda2bbc4f3413c5619bdfabdff`. The existing FileBrowser server revision observed by the operator was `8ff37ef0da322aa2194d9ef37e26eb7f7035cbb2`; backend and deployment files between that revision and this branch base were identical. These are different component identities. This document is a candidate implementation record, not proof of production deployment.

## Implemented interface

`POST /api/resources/products` uses the normal authenticated resource and audit middleware. `server.productMaterialsUsers` is an exact service-user allowlist, default empty. Existing user permissions, token intersection, current Source/Scope and per-path checks still apply. No model receives a service token or host path.

- `inspect`: bounded ZIP metadata and streamed member CRC/SHA-256 validation.
- `preview`: one selected PNG/JPEG member, verified against the inspected package. The trusted adapter invokes the installed native vision tool and includes the actual image in the model result.
- `import`: explicit brand/product/specification/version, archive digest and a complete member classification/evidence map. Missing or ambiguous identity is not guessed; `pending` is an explicit category. It retains the original ZIP and creates a new version. It does not overwrite an employee version.
- `export`: a confirmed complete version and explicit categories. Every selected source is authorized, frozen, checked and packed. The ZIP is reread to compare all members, then sources are rechecked. Stable temporary metadata makes identical export retries byte-identical. Source metadata is unchanged.

Limits are coordinated at 128 MiB compressed/upload/output, 512 MiB expanded, 32 MiB per member and 2,000 entries, with a 200:1 expansion bound. ZIP links, special files, encryption, path traversal, collisions and malformed length/CRC are rejected. Normal Chinese names, spaces and parentheses survive. Product/version/output labels also reject Windows reserved names, control/format characters and illegal filename characters.

Import publishes `product-materials.pending.json` first and `product-materials.json` last. An existing version requires an exact matching pending intent. Retries validate all files, including after process restart. New publication uses exclusive directory reservation and hard-link no-replace publication; unsupported filesystems fail closed. Changed bytes return 409. Partial imports remain accurately pending and are not deleted or advertised complete. This protects normal scoped API activity; it does not claim to defeat an administrator replacing filesystem parents outside the service.

## Hermes and Gateway contract

Two opt-in tools are registered through the normal plugin loader:

1. `filebrowser_ingest_product_zip`: accepts only the current attachment ID, resolves the active host binding, verifies the inbound workcopy and streams it through the Go client to the scoped enterprise incoming directory. The original upload is retained. It returns an inspected manifest, not a host path.
2. `filebrowser_product_materials`: list/search/stat/inspect/preview/import/export, fixed configured enterprise source and root. A trusted current Gateway task is required, with an exact allowlist of enterprise identity, thread, source account, private chat, Profile reference and revision. Every subprocess is bounded and checks task liveness while running. Model input cannot supply an executable, token, URL, filesystem path or `apply` switch.

Generated export descriptor fields are `source`, `path`, `name`, `mime_type=application/zip`, `size_bytes`, `sha256`, and `manifest`. The already loaded Gateway return plugin registers an opaque current-task `file_ref`. `cf_return_current_chat` then imports the ZIP server-to-server from a fixed TLS FileBrowser source/root. ZIP output is not routed back through the AI host. Inbound staging still uses the existing protected host workcopy once; formal extraction, archive and query happen on FileBrowser. Old attachment handles and original-only followup capabilities cannot authorize a new ZIP.

A normal user can ask to preserve and classify a product package, then ask to export the latest *confirmed* product version. Tools expose real listings and preview content; product/version ambiguity must be clarified. This candidate does not imply support for arbitrary natural-language attachment-reference resolution or full chat history retrieval.

## Deployment boundary

No database migration is added by this FileBrowser change. Build server and independent Go client from the exact candidate commit. Preserve the existing TLS, Source/mounts and data; do not upgrade Hermes. Back up and actually verify the existing database/configuration before a server switch. Keep the old server image by digest. New product files and operation receipts are ordinary retained data, not a reason to delete data during rollback.

Enable only the approved service username in `server.productMaterialsUsers`; create a new client config with the existing protected credential and verified CA, read/write roots limited to this business scope and the bounded limits above. Do not replace the old read-only config or use an Admin token. The operator must verify current effective permissions rather than infer them from a token filename.

Hermes config adds `product_enabled`, `product_config_path`, `product_source`, `product_root`, and exact `product_allowed_bindings`; existing `client_path` / `client_sha256` pin the new Go client. Add `cf_filebridge_products` only to the approved Profile, and `filebrowser_ingest_product_zip` to the existing inbound consumer allowlist. The installed Gateway companion must provide the trusted-context and enterprise-return middleware wrappers. Keep model/vision settings unchanged. Verify actual tool schemas and handlers through official middleware before enabling a real window.

Existing complete PDF and PNG read/return results are preserved. The new ZIP candidate does not change image routing to claim lossless PNG file return.

## Verification and evidence boundary

Local Windows Go 1.26.8 product HTTP tests pass, including real bearer-token and audit middleware, token/account intersection, current scope/revocation, default-off/wrong-user denial, unsafe ZIP limits, unknown-version protection, exact pending recovery and deterministic export. Independent Go client and inbound worker regressions pass.

Plugin regression initially failed in an unprepared Python environment (missing parser packages/worker), then in the production PDF/PNG-only parser environment for Office dependencies. A separate test-only virtual environment installed the repository's unchanged, fully hashed parser requirements. The full suite then passed: 158 tests, one explicit environment-dependent skip. No production dependency was installed for this test.

The official joint probe uses Hermes 427d605 source/loading/middleware, real scoped TLS FileBrowser APIs, the new Go client, Gateway database/artifact/delivery code, a deterministic local model and a WeChat protocol substitute. It processed a complete real 12-image product set as an independently derived 18,166,503-byte ZIP (the source directory contained no original ZIP). Four `.WeDrive` metadata files were excluded, recorded privately, and original images were not changed. Inspect, actual image preview into model input, complete import, export, current return reference, Artifact and substitute Delivery passed. Generated ZIP: 18,167,075 bytes, SHA-256 `77c3ad0cf868a6e3862fbe949c679b5cea73def4596ffcd3e4160f1e47add498`; all 12 selected member digests matched their originals. These are isolated-model/protocol-substitute results, not live model, production deployment or employee receipt.

The first external fixture had an uninitialized test audit map, causing HTTP 500 before file publication; fixed with the existing audit-store constructor. Its evidence is preserved. Later replay exposed temporary snapshot timestamps and conflict-status mapping; fixed by deterministic timestamps and explicit 409, with regression coverage. No failed production tasks were replayed.

Private evidence is retained by the operator under the task's `enterprise-product-materials` worktree `.task-artifacts`: full product input manifest, scoped test logs, `joint-fixture-*` and companion Gateway `official-product-08`. No credentials, image bodies or private logs are included in this document. CI results must be read at the exact PR head; historical FileBridge fixture-download/lint failures are not silently relabeled successful.

## Remaining limits

This first commit implements querying and safe creation/classification/export of immutable product versions. General existing-file move/rename/update/delete with recovery and concurrent-version checks is a separate follow-on; it is not exposed by these tools yet. Existing unrestricted PATCH/DELETE endpoints are deliberately not surfaced to the model as a substitute for that missing protection. Live deployment, real-model business classification and actual recipient ZIP verification remain separate operator steps.
