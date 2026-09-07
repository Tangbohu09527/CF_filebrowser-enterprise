//go:build !windows

package http

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/indexing/iteminfo"
)

func TestResourceAggregateRejectsHardlinksAndCanonicalAliases(t *testing.T) {
	for _, kind := range []string{"hardlink", "allowed-alias", "denied-canonical", "outside-source", "outside-scope", "dangling", "loop", "directory-alias"} {
		t.Run(kind, func(t *testing.T) {
			source, user, token := resourceAggregateFixture(t, true)
			target := filepath.Join(source, "public", "nested", "inner.txt")
			requestPath := "/public"
			if kind == "outside-source" || kind == "outside-scope" {
				outside := t.TempDir()
				if kind == "outside-scope" {
					outside = filepath.Join(source, "outside")
					if mkdirErr := os.Mkdir(outside, 0o755); mkdirErr != nil {
						t.Fatal(mkdirErr)
					}
					user.Scopes = []users.SourceScope{{Name: source, Scope: "/public"}}
					if updateErr := store.Users.Update(user, true, "Scopes"); updateErr != nil {
						t.Fatal(updateErr)
					}
					requestPath = "/"
				}
				target = filepath.Join(outside, "private.txt")
				if writeErr := os.WriteFile(target, []byte("outside aggregate secret bytes"), 0o600); writeErr != nil {
					t.Fatal(writeErr)
				}
			}
			alias := filepath.Join(source, "public", "alias.txt")
			switch kind {
			case "dangling":
				target = filepath.Join(source, "missing.txt")
			case "loop":
				target = alias
			case "directory-alias":
				target = filepath.Join(source, "public", "nested")
			}
			if kind == "hardlink" {
				if linkErr := os.Link(target, alias); linkErr != nil {
					t.Fatal(linkErr)
				}
			} else {
				if linkErr := os.Symlink(target, alias); linkErr != nil {
					t.Fatal(linkErr)
				}
			}
			if kind == "denied-canonical" {
				if denyErr := store.Access.DenyUser(source, "/public/nested/inner.txt", user.Username); denyErr != nil {
					t.Fatal(denyErr)
				}
			}
			inodeSize := resourceAggregateInodeSize(t, source)
			response := resourceDisplayRequest(t, user, token, requestPath)
			if kind == "allowed-alias" {
				entryInfo, statErr := os.Lstat(alias)
				if statErr != nil {
					t.Fatal(statErr)
				}
				if response.Size != 22+entryInfo.Size() {
					t.Fatal("authorized alias must count link bytes without repeating target data")
				}
				return
			}
			if response.Size != inodeSize {
				t.Fatal("aggregate guessed hardlink ownership or followed a canonical alias")
			}
		})
	}
}

func TestResourceAggregateCountsSameDirectorySymlinkEntries(t *testing.T) {
	for _, logical := range []bool{false, true} {
		name := "physical"
		if logical {
			name = "logical"
		}
		t.Run(name, func(t *testing.T) {
			source, user, token := resourceAggregateFixture(t, logical)
			for _, linkName := range []string{"first.txt", "second.txt"} {
				if linkErr := os.Symlink("inner.txt", filepath.Join(source, "public", "nested", linkName)); linkErr != nil {
					t.Fatal(linkErr)
				}
			}
			user.Scopes = []users.SourceScope{{Name: source, Scope: "/public"}}
			if updateErr := store.Users.Update(user, true, "Scopes"); updateErr != nil {
				t.Fatal(updateErr)
			}
			response := resourceDisplayRequest(t, user, token, "/")
			want := int64(12288)
			if logical {
				want = 22 + 2*int64(len("inner.txt"))
			}
			if response.Size != want {
				t.Fatalf("two same-directory links: size=%d want=%d", response.Size, want)
			}
		})
	}
}

func TestResourceAggregateDiscardsSymlinkChangesAndRevocation(t *testing.T) {
	for _, mutation := range []string{"entry-replaced", "target-replaced", "target-denied", "entry-denied"} {
		t.Run(mutation, func(t *testing.T) {
			source, user, token := resourceAggregateFixture(t, true)
			alias := filepath.Join(source, "public", "alias.txt")
			target := filepath.Join(source, "public", "nested", "inner.txt")
			if linkErr := os.Symlink("nested/inner.txt", alias); linkErr != nil {
				t.Fatal(linkErr)
			}
			inodeSize := resourceAggregateInodeSize(t, source)
			resourceAggregateCollectedHook = func() {
				switch mutation {
				case "entry-replaced":
					if renameErr := os.Rename(alias, filepath.Join(source, "detached-link")); renameErr != nil {
						t.Fatal(renameErr)
					}
					if linkErr := os.Symlink("outer.txt", alias); linkErr != nil {
						t.Fatal(linkErr)
					}
				case "target-replaced":
					if renameErr := os.Rename(target, filepath.Join(source, "detached-target")); renameErr != nil {
						t.Fatal(renameErr)
					}
					if writeErr := os.WriteFile(target, []byte("replacement target"), 0o600); writeErr != nil {
						t.Fatal(writeErr)
					}
				case "target-denied":
					if denyErr := store.Access.DenyUser(source, "/public/nested/inner.txt", user.Username); denyErr != nil {
						t.Fatal(denyErr)
					}
				case "entry-denied":
					if denyErr := store.Access.DenyUser(source, "/public/alias.txt", user.Username); denyErr != nil {
						t.Fatal(denyErr)
					}
				}
			}
			response := resourceDisplayRequest(t, user, token, "/public")
			if response.Size != inodeSize {
				t.Fatal("changed or denied symlink identity exposed an aggregate")
			}
		})
	}
}

func TestResourceAggregateFinalBatchIncludesLinkTargetOutsideEnumeratedTree(t *testing.T) {
	source, user, token := resourceAggregateFixture(t, true)
	outside := filepath.Join(source, "outside.txt")
	if writeErr := os.WriteFile(outside, []byte("allowed target outside aggregate tree"), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	if linkErr := os.Symlink("../outside.txt", filepath.Join(source, "public", "alias.txt")); linkErr != nil {
		t.Fatal(linkErr)
	}
	target, resolveErr := resolveAuthenticatedReadTarget(user, "source1", "/public")
	if resolveErr != nil {
		t.Fatal(resolveErr)
	}
	walk, collectErr := collectAuthenticatedResourceAggregates(context.Background(), &requestContext{user: user, token: token}, target)
	if collectErr != nil || walk == nil {
		t.Fatalf("prepare aggregate with authorized external-tree link target: %v", collectErr)
	}
	if denyErr := store.Access.DenyUser(source, "/outside.txt", user.Username); denyErr != nil {
		t.Fatal(denyErr)
	}
	info := &iteminfo.ExtendedFileInfo{FileInfo: iteminfo.FileInfo{ItemInfo: iteminfo.ItemInfo{Size: target.Info.Size()}}}
	walk.apply(user, target, info)
	if info.Size != target.Info.Size() {
		t.Fatal("final ACL batch omitted target outside enumerated tree")
	}
}
