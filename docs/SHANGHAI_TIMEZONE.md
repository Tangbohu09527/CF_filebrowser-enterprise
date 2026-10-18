# Shanghai deployment timezone

Official and shared-host Compose now default FileBrowser (and the optional Nginx proxy) to `TZ=Asia/Shanghai`; full/slim images set the same default and retain their existing tzdata dependency. No Source/Scope, credentials, mounts, file permissions or business data change.

The backup timer now explicitly schedules 02:30 Asia/Shanghai plus its existing randomized delay of up to 30 minutes. This changes future wall-clock scheduling on a host previously using another zone; inspect the current timer and its last/next execution before controlled reload. `Persistent=true` remains, so check catch-up behavior rather than blindly starting the timer. Existing backup names, manifests and audit `timestampUtc` stay UTC. No historical timestamp conversion is performed.

FileBrowser audit and token expiry use UTC/epoch; indexing uses Unix-second slots and durations. A process display-zone change does not alter those instants. Existing frontend timestamp rendering follows the browser locale; this change does not rewrite client settings. Verify actual container zoneinfo/date and relevant timer output after deployment. Source/isolated checks do not establish production state.

The targeted deployment test checks both Compose profiles, runtime zoneinfo availability declared by the Dockerfiles and the explicit backup calendar/UTC record boundary. Existing deployment CI additionally validates the actual systemd unit syntax.

Local targeted result: `python -m unittest discover -s deploy/tests -p test_timezone_defaults.py -v` passed all three tests. Actual systemd syntax and rendered deployment checks are delegated to the existing Linux CI job; they were not executed on Windows.
