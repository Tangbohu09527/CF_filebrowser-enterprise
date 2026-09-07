package access_test

import (
	"testing"

	accesspkg "github.com/gtsteffaniak/filebrowser/backend/database/access"
)

func TestPermittedPathsFreshUsesCurrentRulesAndGroups(t *testing.T) {
	const username = "aggregate-reader"
	storage, source := newPermittedFreshTestStorage(t, username)
	paths := []string{"/documents", "/documents/a.txt", "/documents/nested/b.txt"}
	if !storage.PermittedPathsFresh(source, paths, username) {
		t.Fatal("initial aggregate paths should be permitted")
	}
	if denyErr := storage.DenyUser(source, paths[2], username); denyErr != nil {
		t.Fatal(denyErr)
	}
	accesspkg.SetPermissionCacheValueForTest(source, paths[2], username, true)
	if storage.PermittedPathsFresh(source, paths, username) {
		t.Fatal("a cached allow bypassed a current descendant denial")
	}
	removed, removeErr := storage.RemoveDenyUser(source, paths[2], username)
	if removeErr != nil || !removed {
		t.Fatalf("remove denial: removed=%t err=%v", removed, removeErr)
	}
	if groupErr := storage.AddUserToGroup("aggregate-readers", username); groupErr != nil {
		t.Fatal(groupErr)
	}
	if denyErr := storage.DenyGroup(source, paths[2], "aggregate-readers"); denyErr != nil {
		t.Fatal(denyErr)
	}
	if storage.PermittedPathsFresh(source, paths, username) {
		t.Fatal("a current group denial was omitted from the aggregate check")
	}
	if !storage.PermittedPathsFresh(source, paths[:2], username) {
		t.Fatal("denied descendant unexpectedly denied its allowed ancestors")
	}
}

func TestPermittedPathsFreshRejectsUnboundedOrInvalidInput(t *testing.T) {
	storage, source := newPermittedFreshTestStorage(t, "aggregate-limit-reader")
	for _, paths := range [][]string{nil, {""}, {"relative"}, make([]string, 8193)} {
		if storage.PermittedPathsFresh(source, paths, "aggregate-limit-reader") {
			t.Fatal("invalid aggregate path batch was accepted")
		}
	}
	if storage.PermittedPathsFresh("missing-source", []string{"/"}, "aggregate-limit-reader") {
		t.Fatal("unknown source was accepted")
	}
}
