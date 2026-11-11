# Explicit user Source allowlists

`User.strictScopes` is a persisted, administrator-controlled opt-in. Its default
is `false`, so existing users continue receiving configured `defaultEnabled`
Sources during ordinary default application and startup normalization.

With `strictScopes: true`, the user's explicit `scopes` are the complete Source
allowlist. Creation and startup do not add default Sources. An empty allowlist
denies every Source. Existing display-name/path normalization and per-Source
directory scope semantics still apply; this does not make originals editable or
grant any file permission.

All file operations continue using the existing central user Source checks,
including metadata/listing, downloads, creation, and trash/list/get/restore.
Full API tokens retain their existing permission intersection with the current
user. The policy does not change signing keys, passwords, token formats, token
records, other users, or global Source configuration.

## Administrative API

An administrator may supply `strictScopes: true` when creating a new user through
`POST /api/users`. Non-administrators cannot create users or change this field.

Changing an existing user's policy requires an explicit `StrictScopes` entry in
the `which` list and a non-null JSON boolean. The existing actor password
confirmation and administrator checks continue to apply. For example, an
administrator can correct one previously broadened account's allowlist and
enable the policy in the same request:

```json
{
  "which": ["Scopes", "StrictScopes"],
  "data": {
    "id": 123,
    "strictScopes": true,
    "scopes": [{"name": "approved-originals-source", "scope": "/"}]
  }
}
```

The ID and Source above are examples. Resolve and verify the intended existing
service identity before updating it. This operation preserves its password and
existing tokens; it does not require reissuing a token.

Omitting the JSON field, or providing `null`, while explicitly selecting
`StrictScopes` is a bad request. A normal `which: ["all"]` update, or an omitted
`which`, cannot change the protection flag, even if a client includes `false`.
This prevents older management forms from silently disabling it. To deliberately
disable the policy, an administrator must explicitly select `StrictScopes` and
provide `false`.

## Upgrade and acceptance boundary

Setting the flag alone does not remove Sources previously added by older
startup code. Repairing such an account requires its intended `Scopes` and
`StrictScopes` to be explicitly corrected together, followed by readback showing
`strictScopes: true` and exactly the approved allowlist. A successful PUT alone is
insufficient: older versions can ignore unknown JSON fields.

Versions including `c7a529e6` and `4750a97c` do not implement this policy. Do not
downgrade a protected account to them and claim Source isolation is retained.
There is no automatic rollback, password reset, token revocation or token
reissuance in this change. Production correction or upgrade needs a separately
reviewed operation for the intended account only.

The regression uses temporary persistent databases and separate startup
processes with an enterprise Source whose `defaultEnabled` remains true, and a
private originals Source whose default remains false. Acceptance must reuse the
same first API token after startup, prove allowed originals access, and prove
denial at actual cross-Source file and trash endpoints. Self authentication alone
does not prove the Source boundary.
