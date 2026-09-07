//go:build !windows

package http

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

func TestResourceAggregateRejectsHardlinksAndCanonicalAliases(t *testing.T) {
	for _, kind := range []string{"hardlink", "allowed-alias", "denied-canonical", "outside-source", "outside-scope"} {
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
			if response.Size != inodeSize {
				t.Fatal("aggregate guessed hardlink ownership or followed a canonical alias")
			}
		})
	}
}
