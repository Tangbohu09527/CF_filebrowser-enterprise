# Signing key startup and recovery

The JWT signing key must remain stable across restart and database restore.
Fresh databases preserve an explicitly configured `auth.key` or
`FILEBROWSER_JWT_TOKEN_SECRET`. Only an unconfigured fresh database generates a
new key: 64 cryptographically random bytes encoded as lossless hexadecimal text.
The existing random-key utility and unrelated authentication methods are unchanged.
Fresh explicit input must be lossless UTF-8 text; rejection occurs before creating
the database and does not impose a new key-length or entropy rule on legacy values.

For an existing database, startup reads the saved key before initializing stores
that write authentication defaults or version records. Only `Auth.Key` is restored;
current file/environment settings, including Source configuration, are retained.
An explicit key that differs from a nonempty saved key stops startup without
changing database records. A missing/unreadable settings record also stops startup.
If the record exists but its key is empty, an explicit trusted key may be used at
runtime without rewriting that record; this configuration must remain available
for subsequent restarts. With neither key, startup refuses an empty or newly
invented key. No password, user, permission or API-token record is replaced.

## Legacy boundary

Older fresh setup stored raw random bytes as a string. The database's JSON codec
can replace invalid UTF-8 bytes, so its saved value may already differ from the
key used to issue original tokens. Such original bytes cannot be reconstructed
from replacement characters. A nonempty legacy value is restored verbatim; this
change neither guesses its history nor reformats it, and does not claim that
already affected tokens can be recovered. Valid explicit Unicode keys remain valid.

Before a production upgrade, preserve the database, configuration and approved
secret backups, and check how the active key was configured without printing it.
Restoring the exact original key requires an existing trusted copy. Unknown key
history, conflicts or unavailable originals require an operator decision within
the user's authorization; this fix does not authorize rotating keys or silently
issuing replacement tokens. Keep the historical affected credentials and evidence.

The Go regression tests use public synthetic credentials and temporary databases
in separate processes. They cover fresh generation, explicit keys, real restart,
unchanged user/token records, current Source settings, refusal without writes,
database-lock release, the legacy JSON-loss boundary, and secret-free debug output.
Candidate-image and real-environment acceptance remain separate checks.
