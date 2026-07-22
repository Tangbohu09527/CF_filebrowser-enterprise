package http

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	dbshare "github.com/gtsteffaniak/filebrowser/backend/database/share"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/preview"
)

func TestPublicShareWriteAuthorization(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)
	if preview.GetService() == nil {
		if err := preview.StartPreviewGenerator(1, filepath.Join(filepath.Dir(sourcePath), "public-write-preview-cache")); err != nil {
			t.Fatal(err)
		}
	}
	router := newPublicWriteSecurityRouter()

	t.Run("create-only token snapshot cannot overwrite an existing file", func(t *testing.T) {
		owner := savePublicWriteOwner(t, sourcePath, "public-create-only-owner", users.Permissions{
			Share:  true,
			Create: true,
			Modify: true,
		})
		savePublicWriteShare(t, sourcePath, owner, "public-create-only-share", dbshare.CapabilitySnapshot{
			Share:  true,
			Create: true,
		})

		target := filepath.Join(sourcePath, "public", "create-only-existing.txt")
		if err := os.WriteFile(target, []byte("original"), 0o644); err != nil {
			t.Fatal(err)
		}

		response := requestPublicWrite(router, http.MethodPost, "public-create-only-share", "/create-only-existing.txt", url.Values{
			"override": {"true"},
		}, strings.NewReader("replaced"))
		if response.Code != http.StatusForbidden {
			t.Fatalf("status: got %d, want %d; body=%s", response.Code, http.StatusForbidden, response.Body.String())
		}
		content, err := os.ReadFile(target)
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != "original" {
			t.Fatalf("create-only token overwrote target: got %q", content)
		}
	})

	t.Run("create-only upload share preserves conflict response without replacement", func(t *testing.T) {
		owner := savePublicWriteOwner(t, sourcePath, "public-create-conflict-owner", users.Permissions{
			Share:  true,
			Create: true,
		})
		link := savePublicWriteShare(t, sourcePath, owner, "public-create-conflict-share", dbshare.CapabilitiesFromPermissions(owner.Permissions))
		link.ShareType = "upload"
		link.AllowReplacements = false
		if err := store.Share.Save(link); err != nil {
			t.Fatal(err)
		}

		target := filepath.Join(sourcePath, "public", "create-conflict-existing.txt")
		if err := os.WriteFile(target, []byte("original"), 0o644); err != nil {
			t.Fatal(err)
		}

		response := requestPublicWrite(router, http.MethodPost, link.Hash, "/create-conflict-existing.txt", nil, strings.NewReader("must not replace"))
		if response.Code != http.StatusConflict {
			t.Fatalf("status: got %d, want %d; body=%s", response.Code, http.StatusConflict, response.Body.String())
		}
		content, err := os.ReadFile(target)
		if err != nil || string(content) != "original" {
			t.Fatalf("conflicting upload changed target: content=%q error=%v", content, err)
		}
	})

	t.Run("modify-only token snapshot cannot create a missing file", func(t *testing.T) {
		owner := savePublicWriteOwner(t, sourcePath, "public-modify-only-owner", users.Permissions{
			Share:  true,
			Create: true,
			Modify: true,
		})
		savePublicWriteShare(t, sourcePath, owner, "public-modify-only-share", dbshare.CapabilitySnapshot{
			Share:  true,
			Modify: true,
		})

		target := filepath.Join(sourcePath, "public", "modify-only-missing.txt")
		response := requestPublicWrite(router, http.MethodPost, "public-modify-only-share", "/modify-only-missing.txt", nil, strings.NewReader("created"))
		if response.Code != http.StatusForbidden {
			t.Fatalf("status: got %d, want %d; body=%s", response.Code, http.StatusForbidden, response.Body.String())
		}
		if _, err := os.Stat(target); !os.IsNotExist(err) {
			t.Fatalf("modify-only token created target: stat error=%v", err)
		}
	})

	t.Run("owner Modify revocation immediately blocks replacement", func(t *testing.T) {
		owner := savePublicWriteOwner(t, sourcePath, "public-modify-revoked-owner", users.Permissions{
			Share:  true,
			Create: true,
			Modify: true,
		})
		savePublicWriteShare(t, sourcePath, owner, "public-modify-revoked-share", dbshare.CapabilitiesFromPermissions(owner.Permissions))
		owner.Permissions.Modify = false
		if err := store.Users.Update(owner, true, "Permissions"); err != nil {
			t.Fatalf("revoke Modify: %v", err)
		}

		target := filepath.Join(sourcePath, "public", "modify-revoked-existing.txt")
		if err := os.WriteFile(target, []byte("original"), 0o644); err != nil {
			t.Fatal(err)
		}
		response := requestPublicWriteAtRoute(router, http.MethodPost, "/resources", "public-modify-revoked-share", "/modify-revoked-existing.txt", url.Values{
			"override": {"true"},
		}, strings.NewReader("replaced"))
		if response.Code != http.StatusForbidden {
			t.Fatalf("status: got %d, want %d; body=%s", response.Code, http.StatusForbidden, response.Body.String())
		}
		content, err := os.ReadFile(target)
		if err != nil || string(content) != "original" {
			t.Fatalf("revoked Modify changed target: content=%q error=%v", content, err)
		}
	})

	t.Run("owner Create revocation immediately blocks creation", func(t *testing.T) {
		owner := savePublicWriteOwner(t, sourcePath, "public-create-revoked-owner", users.Permissions{
			Share:  true,
			Create: true,
			Modify: true,
		})
		savePublicWriteShare(t, sourcePath, owner, "public-create-revoked-share", dbshare.CapabilitiesFromPermissions(owner.Permissions))
		owner.Permissions.Create = false
		if err := store.Users.Update(owner, true, "Permissions"); err != nil {
			t.Fatalf("revoke Create: %v", err)
		}

		target := filepath.Join(sourcePath, "public", "create-revoked-missing.txt")
		response := requestPublicWriteAtRoute(router, http.MethodPost, "/resources", "public-create-revoked-share", "/create-revoked-missing.txt", nil, strings.NewReader("created"))
		if response.Code != http.StatusForbidden {
			t.Fatalf("status: got %d, want %d; body=%s", response.Code, http.StatusForbidden, response.Body.String())
		}
		if _, err := os.Stat(target); !os.IsNotExist(err) {
			t.Fatalf("revoked Create created target: stat error=%v", err)
		}
	})

	t.Run("non-root scope uses the full logical Access Rule", func(t *testing.T) {
		if err := os.MkdirAll(filepath.Join(sourcePath, "team", "public"), 0o755); err != nil {
			t.Fatal(err)
		}
		owner := savePublicWriteOwnerWithScope(t, sourcePath, "/team", "public-scoped-owner", users.Permissions{
			Share:  true,
			Create: true,
		})
		savePublicWriteShareAtPath(t, sourcePath, owner, "public-scoped-share", "/team/public", dbshare.CapabilitiesFromPermissions(owner.Permissions))
		if err := store.Access.DenyUser(sourcePath, "/team/public/blocked.txt", owner.Username); err != nil {
			t.Fatalf("deny scoped target: %v", err)
		}

		target := filepath.Join(sourcePath, "team", "public", "blocked.txt")
		response := requestPublicWriteAtRoute(router, http.MethodPost, "/resources", "public-scoped-share", "/blocked.txt", nil, strings.NewReader("blocked"))
		if response.Code != http.StatusForbidden {
			t.Fatalf("status: got %d, want %d; body=%s", response.Code, http.StatusForbidden, response.Body.String())
		}
		if _, err := os.Stat(target); !os.IsNotExist(err) {
			t.Fatalf("Access Rule denied target was created: stat error=%v", err)
		}
	})

	t.Run("symlink ancestor cannot escape the share root", func(t *testing.T) {
		owner := savePublicWriteOwner(t, sourcePath, "public-symlink-owner", users.Permissions{
			Share:  true,
			Create: true,
		})
		savePublicWriteShare(t, sourcePath, owner, "public-symlink-share", dbshare.CapabilitiesFromPermissions(owner.Permissions))
		outside := filepath.Join(filepath.Dir(sourcePath), "public-write-outside")
		if err := os.MkdirAll(outside, 0o755); err != nil {
			t.Fatal(err)
		}
		linkPath := filepath.Join(sourcePath, "public", "escape-link")
		if err := os.Symlink(outside, linkPath); err != nil {
			t.Skipf("symlink not available: %v", err)
		}

		response := requestPublicWriteAtRoute(router, http.MethodPost, "/resources", "public-symlink-share", "/escape-link/escaped.txt", nil, strings.NewReader("escaped"))
		if response.Code != http.StatusForbidden {
			t.Fatalf("status: got %d, want %d; body=%s", response.Code, http.StatusForbidden, response.Body.String())
		}
		if _, err := os.Stat(filepath.Join(outside, "escaped.txt")); !os.IsNotExist(err) {
			t.Fatalf("write escaped through symlink: stat error=%v", err)
		}
	})

	t.Run("PATCH missing destination requires Create", func(t *testing.T) {
		owner := savePublicWriteOwner(t, sourcePath, "public-patch-create-owner", users.Permissions{
			Share:  true,
			Modify: true,
		})
		savePublicWriteShareAtPath(t, sourcePath, owner, "public-patch-create-share", "/public", dbshare.CapabilitiesFromPermissions(owner.Permissions))
		source := filepath.Join(sourcePath, "public", "patch-create-source.txt")
		if err := os.WriteFile(source, []byte("source"), 0o644); err != nil {
			t.Fatal(err)
		}
		body := marshalPublicWriteBody(t, MoveCopyRequest{
			Action: "copy",
			Items:  []MoveCopyItem{{FromPath: "/patch-create-source.txt", ToPath: "/patch-create-destination.txt"}},
		})
		response := requestPublicWriteAtRoute(router, http.MethodPatch, "/resources", "public-patch-create-share", "/", nil, body)
		if response.Code != http.StatusForbidden {
			t.Fatalf("status: got %d, want %d; body=%s", response.Code, http.StatusForbidden, response.Body.String())
		}
		if _, err := os.Stat(filepath.Join(sourcePath, "public", "patch-create-destination.txt")); !os.IsNotExist(err) {
			t.Fatalf("PATCH created destination without Create: stat error=%v", err)
		}
	})

	t.Run("PATCH move requires Delete", func(t *testing.T) {
		owner := savePublicWriteOwner(t, sourcePath, "public-patch-delete-owner", users.Permissions{
			Share:  true,
			Create: true,
			Modify: true,
		})
		savePublicWriteShareAtPath(t, sourcePath, owner, "public-patch-delete-share", "/public", dbshare.CapabilitiesFromPermissions(owner.Permissions))
		source := filepath.Join(sourcePath, "public", "patch-move-source.txt")
		if err := os.WriteFile(source, []byte("source"), 0o644); err != nil {
			t.Fatal(err)
		}
		body := marshalPublicWriteBody(t, MoveCopyRequest{
			Action: "move",
			Items:  []MoveCopyItem{{FromPath: "/patch-move-source.txt", ToPath: "/patch-move-destination.txt"}},
		})
		response := requestPublicWriteAtRoute(router, http.MethodPatch, "/resources", "public-patch-delete-share", "/", nil, body)
		if response.Code != http.StatusForbidden {
			t.Fatalf("status: got %d, want %d; body=%s", response.Code, http.StatusForbidden, response.Body.String())
		}
		if _, err := os.Stat(source); err != nil {
			t.Fatalf("PATCH moved source without Delete: %v", err)
		}
	})

	t.Run("PATCH preauthorizes every automatic rename destination", func(t *testing.T) {
		owner := savePublicWriteOwner(t, sourcePath, "public-patch-rename-owner", users.Permissions{
			Share:  true,
			Create: true,
			Modify: true,
		})
		savePublicWriteShareAtPath(t, sourcePath, owner, "public-patch-rename-share", "/public", dbshare.CapabilitiesFromPermissions(owner.Permissions))
		items := []MoveCopyItem{
			{FromPath: "/rename-source-a.txt", ToPath: "/rename-target-a.txt"},
			{FromPath: "/rename-source-b.txt", ToPath: "/rename-target-b.txt"},
		}
		expectedDestinations := make([]string, 0, len(items))
		for _, item := range items {
			if err := os.WriteFile(filepath.Join(sourcePath, "public", strings.TrimPrefix(item.FromPath, "/")), []byte("source"), 0o644); err != nil {
				t.Fatal(err)
			}
			destination := filepath.Join(sourcePath, "public", strings.TrimPrefix(item.ToPath, "/"))
			if err := os.WriteFile(destination, []byte("existing"), 0o644); err != nil {
				t.Fatal(err)
			}
			expectedDestinations = append(expectedDestinations, addVersionSuffix(destination))
		}
		body := marshalPublicWriteBody(t, MoveCopyRequest{Action: "copy", Items: items, Rename: true})
		response := requestPublicWriteAtRoute(router, http.MethodPatch, "/resources", "public-patch-rename-share", "/", nil, body)
		if response.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d; body=%s", response.Code, http.StatusOK, response.Body.String())
		}
		for i, destination := range expectedDestinations {
			if _, err := os.Stat(destination); err != nil {
				t.Fatalf("authorized rename destination was not created for %s: %v", items[i].ToPath, err)
			}
		}
	})

	t.Run("PATCH automatic rename still requires Create", func(t *testing.T) {
		owner := savePublicWriteOwner(t, sourcePath, "public-patch-rename-create-owner", users.Permissions{
			Share: true, Modify: true,
		})
		savePublicWriteShareAtPath(t, sourcePath, owner, "public-patch-rename-create-share", "/public", dbshare.CapabilitiesFromPermissions(owner.Permissions))
		if err := os.WriteFile(filepath.Join(sourcePath, "public", "rename-create-source.txt"), []byte("source"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sourcePath, "public", "rename-create-target.txt"), []byte("existing"), 0o644); err != nil {
			t.Fatal(err)
		}
		body := marshalPublicWriteBody(t, MoveCopyRequest{Action: "copy", Rename: true, Items: []MoveCopyItem{{
			FromPath: "/rename-create-source.txt", ToPath: "/rename-create-target.txt",
		}}})
		response := requestPublicWriteAtRoute(router, http.MethodPatch, "/resources", "public-patch-rename-create-share", "/", nil, body)
		if response.Code != http.StatusForbidden {
			t.Fatalf("status: got %d, want %d; body=%s", response.Code, http.StatusForbidden, response.Body.String())
		}
		if _, err := os.Stat(filepath.Join(sourcePath, "public", "rename-create-target(1).txt")); !os.IsNotExist(err) {
			t.Fatalf("automatic rename created a file without Create: %v", err)
		}
	})

	t.Run("PATCH duplicate destination cannot bypass replacement policy", func(t *testing.T) {
		owner := savePublicWriteOwner(t, sourcePath, "public-patch-duplicate-owner", users.Permissions{
			Share: true, Create: true, Modify: true,
		})
		link := savePublicWriteShareAtPath(t, sourcePath, owner, "public-patch-duplicate-share", "/public", dbshare.CapabilitiesFromPermissions(owner.Permissions))
		link.AllowReplacements = false
		if err := store.Share.Save(link); err != nil {
			t.Fatal(err)
		}
		first := filepath.Join(sourcePath, "public", "duplicate-source-a.txt")
		second := filepath.Join(sourcePath, "public", "duplicate-source-b.txt")
		if err := os.WriteFile(first, []byte("first"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(second, []byte("second"), 0o644); err != nil {
			t.Fatal(err)
		}
		destination := filepath.Join(sourcePath, "public", "duplicate-destination.txt")
		body := marshalPublicWriteBody(t, MoveCopyRequest{Action: "copy", Items: []MoveCopyItem{
			{FromPath: "/duplicate-source-a.txt", ToPath: "/duplicate-destination.txt"},
			{FromPath: "/duplicate-source-b.txt", ToPath: "/duplicate-destination.txt"},
		}})
		response := requestPublicWriteAtRoute(router, http.MethodPatch, "/resources", link.Hash, "/", nil, body)
		if response.Code != http.StatusConflict {
			t.Fatalf("status: got %d, want %d; body=%s", response.Code, http.StatusConflict, response.Body.String())
		}
		if _, err := os.Stat(destination); !os.IsNotExist(err) {
			t.Fatalf("duplicate manifest mutated destination: stat error=%v", err)
		}
	})

	t.Run("PATCH automatic rename reserves a unique destination per item", func(t *testing.T) {
		owner := savePublicWriteOwner(t, sourcePath, "public-patch-reservation-owner", users.Permissions{
			Share: true, Create: true, Modify: true,
		})
		link := savePublicWriteShareAtPath(t, sourcePath, owner, "public-patch-reservation-share", "/public", dbshare.CapabilitiesFromPermissions(owner.Permissions))
		link.AllowReplacements = false
		if err := store.Share.Save(link); err != nil {
			t.Fatal(err)
		}
		for name, content := range map[string]string{
			"reservation-source-a.txt": "first",
			"reservation-source-b.txt": "second",
			"reservation-target.txt":   "existing",
		} {
			if err := os.WriteFile(filepath.Join(sourcePath, "public", name), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		body := marshalPublicWriteBody(t, MoveCopyRequest{Action: "copy", Rename: true, Items: []MoveCopyItem{
			{FromPath: "/reservation-source-a.txt", ToPath: "/reservation-target.txt"},
			{FromPath: "/reservation-source-b.txt", ToPath: "/reservation-target.txt"},
		}})
		response := requestPublicWriteAtRoute(router, http.MethodPatch, "/resources", link.Hash, "/", nil, body)
		if response.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d; body=%s", response.Code, http.StatusOK, response.Body.String())
		}
		for name, expected := range map[string]string{
			"reservation-target(1).txt": "first",
			"reservation-target(2).txt": "second",
		} {
			content, err := os.ReadFile(filepath.Join(sourcePath, "public", name))
			if err != nil || string(content) != expected {
				t.Fatalf("reserved destination %s: content=%q err=%v", name, content, err)
			}
		}
	})

	t.Run("PATCH rejects overlapping destinations before mutation", func(t *testing.T) {
		owner := savePublicWriteOwner(t, sourcePath, "public-patch-overlap-owner", users.Permissions{
			Share: true, Create: true, Modify: true,
		})
		link := savePublicWriteShareAtPath(t, sourcePath, owner, "public-patch-overlap-share", "/public", dbshare.CapabilitiesFromPermissions(owner.Permissions))
		link.AllowReplacements = false
		if err := store.Share.Save(link); err != nil {
			t.Fatal(err)
		}
		directorySource := filepath.Join(sourcePath, "public", "overlap-directory-source")
		if err := os.MkdirAll(directorySource, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directorySource, "child.txt"), []byte("directory child"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sourcePath, "public", "overlap-file-source.txt"), []byte("separate file"), 0o644); err != nil {
			t.Fatal(err)
		}
		body := marshalPublicWriteBody(t, MoveCopyRequest{Action: "copy", Items: []MoveCopyItem{
			{FromPath: "/overlap-directory-source", ToPath: "/overlap-destination"},
			{FromPath: "/overlap-file-source.txt", ToPath: "/overlap-destination/child.txt"},
		}})
		response := requestPublicWriteAtRoute(router, http.MethodPatch, "/resources", link.Hash, "/", nil, body)
		if response.Code != http.StatusConflict {
			t.Fatalf("status: got %d, want %d; body=%s", response.Code, http.StatusConflict, response.Body.String())
		}
		if _, err := os.Stat(filepath.Join(sourcePath, "public", "overlap-destination")); !os.IsNotExist(err) {
			t.Fatalf("overlapping manifest mutated destination: stat error=%v", err)
		}
	})

	t.Run("PATCH rejects a destination inside another planned source tree", func(t *testing.T) {
		owner := savePublicWriteOwner(t, sourcePath, "public-patch-cross-plan-owner", users.Permissions{
			Share: true, Create: true, Modify: true,
		})
		savePublicWriteShareAtPath(t, sourcePath, owner, "public-patch-cross-plan-share", "/public", dbshare.CapabilitiesFromPermissions(owner.Permissions))
		treeSource := filepath.Join(sourcePath, "public", "cross-plan-tree")
		if err := os.MkdirAll(treeSource, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(treeSource, "existing.txt"), []byte("existing"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sourcePath, "public", "cross-plan-file.txt"), []byte("source"), 0o644); err != nil {
			t.Fatal(err)
		}
		body := marshalPublicWriteBody(t, MoveCopyRequest{Action: "copy", Items: []MoveCopyItem{
			{FromPath: "/cross-plan-file.txt", ToPath: "/cross-plan-tree/generated.txt"},
			{FromPath: "/cross-plan-tree", ToPath: "/cross-plan-copy"},
		}})
		response := requestPublicWriteAtRoute(router, http.MethodPatch, "/resources", "public-patch-cross-plan-share", "/", nil, body)
		if response.Code != http.StatusConflict {
			t.Fatalf("status: got %d, want %d; body=%s", response.Code, http.StatusConflict, response.Body.String())
		}
		for _, target := range []string{
			filepath.Join(treeSource, "generated.txt"),
			filepath.Join(sourcePath, "public", "cross-plan-copy"),
		} {
			if _, err := os.Stat(target); !os.IsNotExist(err) {
				t.Fatalf("cross-plan overlap mutated %s: %v", target, err)
			}
		}
	})

	t.Run("PATCH authorizes every directory source and destination member", func(t *testing.T) {
		for _, test := range []struct {
			name       string
			deniedPath func(sourceName, destinationName string) string
		}{
			{name: "source child", deniedPath: func(sourceName, _ string) string { return "/public/" + sourceName + "/blocked.txt" }},
			{name: "destination child", deniedPath: func(_, destinationName string) string { return "/public/" + destinationName + "/blocked.txt" }},
		} {
			t.Run(test.name, func(t *testing.T) {
				suffix := strings.ReplaceAll(test.name, " ", "-")
				owner := savePublicWriteOwner(t, sourcePath, "public-patch-member-"+suffix+"-owner", users.Permissions{
					Share: true, Create: true, Modify: true,
				})
				link := savePublicWriteShareAtPath(t, sourcePath, owner, "public-patch-member-"+suffix+"-share", "/public", dbshare.CapabilitiesFromPermissions(owner.Permissions))
				sourceName := "member-" + suffix + "-source"
				destinationName := "member-" + suffix + "-destination"
				sourceDirectory := filepath.Join(sourcePath, "public", sourceName)
				if err := os.MkdirAll(sourceDirectory, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(sourceDirectory, "blocked.txt"), []byte("blocked member"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := store.Access.DenyUser(sourcePath, test.deniedPath(sourceName, destinationName), owner.Username); err != nil {
					t.Fatal(err)
				}
				body := marshalPublicWriteBody(t, MoveCopyRequest{Action: "copy", Items: []MoveCopyItem{{
					FromPath: "/" + sourceName,
					ToPath:   "/" + destinationName,
				}}})
				response := requestPublicWriteAtRoute(router, http.MethodPatch, "/resources", link.Hash, "/", nil, body)
				if response.Code != http.StatusForbidden {
					t.Fatalf("status: got %d, want %d; body=%s", response.Code, http.StatusForbidden, response.Body.String())
				}
				if _, err := os.Stat(filepath.Join(sourcePath, "public", destinationName)); !os.IsNotExist(err) {
					t.Fatalf("denied directory member was copied: stat error=%v", err)
				}
			})
		}
	})

	t.Run("PATCH rejects a symlink member before copying a directory", func(t *testing.T) {
		owner := savePublicWriteOwner(t, sourcePath, "public-patch-member-symlink-owner", users.Permissions{
			Share: true, Create: true, Modify: true,
		})
		link := savePublicWriteShareAtPath(t, sourcePath, owner, "public-patch-member-symlink-share", "/public", dbshare.CapabilitiesFromPermissions(owner.Permissions))
		sourceDirectory := filepath.Join(sourcePath, "public", "member-symlink-source")
		if err := os.MkdirAll(sourceDirectory, 0o755); err != nil {
			t.Fatal(err)
		}
		outside := filepath.Join(t.TempDir(), "outside-secret.txt")
		if err := os.WriteFile(outside, []byte("outside secret"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(sourceDirectory, "leak.txt")); err != nil {
			t.Skipf("symlink not available: %v", err)
		}
		body := marshalPublicWriteBody(t, MoveCopyRequest{Action: "copy", Items: []MoveCopyItem{{
			FromPath: "/member-symlink-source",
			ToPath:   "/member-symlink-destination",
		}}})
		response := requestPublicWriteAtRoute(router, http.MethodPatch, "/resources", link.Hash, "/", nil, body)
		if response.Code != http.StatusForbidden {
			t.Fatalf("status: got %d, want %d; body=%s", response.Code, http.StatusForbidden, response.Body.String())
		}
		if _, err := os.Stat(filepath.Join(sourcePath, "public", "member-symlink-destination")); !os.IsNotExist(err) {
			t.Fatalf("symlink member was copied: stat error=%v", err)
		}
	})

	t.Run("directory delete preauthorizes every descendant", func(t *testing.T) {
		deleteRoutes := []struct {
			name string
			bulk bool
		}{
			{name: "single"},
			{name: "bulk", bulk: true},
		}
		descendants := []struct {
			name    string
			symlink bool
		}{
			{name: "ACL-denied child"},
			{name: "symlink child", symlink: true},
		}

		for _, deleteRoute := range deleteRoutes {
			for _, descendant := range descendants {
				t.Run(deleteRoute.name+" "+descendant.name, func(t *testing.T) {
					suffix := strings.ReplaceAll(strings.ToLower(deleteRoute.name+"-"+descendant.name), " ", "-")
					owner := savePublicWriteOwner(t, sourcePath, "public-delete-tree-"+suffix+"-owner", users.Permissions{
						Share:  true,
						Delete: true,
					})
					link := savePublicWriteShareAtPath(t, sourcePath, owner, "public-delete-tree-"+suffix+"-share", "/public", dbshare.CapabilitiesFromPermissions(owner.Permissions))
					link.AllowDelete = true
					if err := store.Share.Save(link); err != nil {
						t.Fatal(err)
					}

					directoryName := "delete-tree-" + suffix
					directoryPath := filepath.Join(sourcePath, "public", directoryName)
					if err := os.MkdirAll(directoryPath, 0o755); err != nil {
						t.Fatal(err)
					}
					childPath := filepath.Join(directoryPath, "blocked.txt")
					const childContent = "preserve denied delete descendant"
					outsidePath := ""
					if descendant.symlink {
						outsidePath = filepath.Join(t.TempDir(), "outside-delete-sentinel.txt")
						if err := os.WriteFile(outsidePath, []byte(childContent), 0o644); err != nil {
							t.Fatal(err)
						}
						if err := os.Symlink(outsidePath, childPath); err != nil {
							t.Skipf("symlink not available: %v", err)
						}
					} else {
						if err := os.WriteFile(childPath, []byte(childContent), 0o644); err != nil {
							t.Fatal(err)
						}
						if err := store.Access.DenyUser(sourcePath, "/public/"+directoryName+"/blocked.txt", owner.Username); err != nil {
							t.Fatal(err)
						}
					}

					var response *httptest.ResponseRecorder
					if deleteRoute.bulk {
						body := marshalPublicWriteBody(t, []BulkDeleteItem{{Path: "/" + directoryName}})
						response = requestPublicWriteAtRoute(router, http.MethodDelete, "/resources/bulk", link.Hash, "/", nil, body)
					} else {
						response = requestPublicWriteAtRoute(router, http.MethodDelete, "/resources", link.Hash, "/"+directoryName, nil, nil)
					}
					if response.Code != http.StatusForbidden {
						t.Errorf("status: got %d, want %d; body=%s", response.Code, http.StatusForbidden, response.Body.String())
					}
					if info, err := os.Stat(directoryPath); err != nil || !info.IsDir() {
						t.Errorf("denied delete changed directory: info=%v err=%v", info, err)
					}
					childInfo, childErr := os.Lstat(childPath)
					if childErr != nil {
						t.Errorf("denied delete removed descendant: %v", childErr)
					}
					if descendant.symlink {
						if childInfo != nil && childInfo.Mode()&os.ModeSymlink == 0 {
							t.Fatalf("denied delete replaced symlink descendant: mode=%v", childInfo.Mode())
						}
						content, err := os.ReadFile(outsidePath)
						if err != nil || string(content) != childContent {
							t.Fatalf("denied delete changed symlink target: content=%q err=%v", content, err)
						}
					} else {
						content, err := os.ReadFile(childPath)
						if err != nil || string(content) != childContent {
							t.Fatalf("denied delete changed ACL-denied descendant: content=%q err=%v", content, err)
						}
					}
				})
			}
		}
	})

	t.Run("bulk delete preauthorizes every body item", func(t *testing.T) {
		owner := savePublicWriteOwner(t, sourcePath, "public-bulk-owner", users.Permissions{
			Share:  true,
			Delete: true,
		})
		link := savePublicWriteShareAtPath(t, sourcePath, owner, "public-bulk-share", "/public", dbshare.CapabilitiesFromPermissions(owner.Permissions))
		link.AllowDelete = true
		if err := store.Share.Save(link); err != nil {
			t.Fatalf("enable share delete: %v", err)
		}
		allowed := filepath.Join(sourcePath, "public", "bulk-allowed.txt")
		denied := filepath.Join(sourcePath, "public", "bulk-denied.txt")
		for _, target := range []string{allowed, denied} {
			if err := os.WriteFile(target, []byte("preserve"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := store.Access.DenyUser(sourcePath, "/public/bulk-denied.txt", owner.Username); err != nil {
			t.Fatalf("deny bulk target: %v", err)
		}
		body := marshalPublicWriteBody(t, []BulkDeleteItem{{Path: "/bulk-allowed.txt"}, {Path: "/bulk-denied.txt"}})
		response := requestPublicWriteAtRoute(router, http.MethodDelete, "/resources/bulk", "public-bulk-share", "/", nil, body)
		if response.Code != http.StatusForbidden {
			t.Errorf("status: got %d, want %d; body=%s", response.Code, http.StatusForbidden, response.Body.String())
		}
		for _, target := range []string{allowed, denied} {
			if _, err := os.Stat(target); err != nil {
				t.Fatalf("bulk authorization failure changed %s: %v", target, err)
			}
		}
	})
}

func newPublicWriteSecurityRouter() http.Handler {
	publicAPI := http.NewServeMux()
	publicAPI.HandleFunc("POST /resources", withHashFile(publicUploadHandler))
	publicAPI.HandleFunc("PUT /resources", withHashFile(publicPutHandler))
	publicAPI.HandleFunc("DELETE /resources", withHashFile(publicDeleteHandler))
	publicAPI.HandleFunc("DELETE /resources/bulk", withHashFile(publicBulkDeleteHandler))
	publicAPI.HandleFunc("PATCH /resources", withHashFile(publicPatchHandler))
	publicAPI.HandleFunc("POST /resources/pause", withHashFile(publicPauseHandler))
	router := http.NewServeMux()
	router.Handle("/public/api/", http.StripPrefix("/public/api", publicAPI))
	return router
}

func savePublicWriteOwner(t *testing.T, sourcePath, username string, permissions users.Permissions) *users.User {
	return savePublicWriteOwnerWithScope(t, sourcePath, "/", username, permissions)
}

func savePublicWriteOwnerWithScope(t *testing.T, sourcePath, scope, username string, permissions users.Permissions) *users.User {
	t.Helper()
	owner := &users.User{
		Username:    username,
		Permissions: permissions,
		Scopes: []users.SourceScope{
			{Name: sourcePath, Scope: scope},
		},
	}
	if err := store.Users.Save(owner, false, false); err != nil {
		t.Fatalf("save owner: %v", err)
	}
	return owner
}

func savePublicWriteShare(t *testing.T, sourcePath string, owner *users.User, hash string, capabilities dbshare.CapabilitySnapshot) *dbshare.Link {
	return savePublicWriteShareAtPath(t, sourcePath, owner, hash, "/public", capabilities)
}

func savePublicWriteShareAtPath(t *testing.T, sourcePath string, owner *users.User, hash, sharePath string, capabilities dbshare.CapabilitySnapshot) *dbshare.Link {
	t.Helper()
	link := &dbshare.Link{
		Hash:   hash,
		UserID: owner.ID,
		CommonShare: dbshare.CommonShare{
			Source:            sourcePath,
			Path:              sharePath,
			ShareType:         "normal",
			AllowCreate:       true,
			AllowModify:       true,
			AllowReplacements: true,
		},
		CapabilityVersion:   dbshare.CurrentCapabilityVersion,
		CreatorCapabilities: capabilities,
	}
	if err := store.Share.Save(link); err != nil {
		t.Fatalf("save share: %v", err)
	}
	return link
}

func requestPublicWrite(router http.Handler, method, hash, path string, extra url.Values, body *strings.Reader) *httptest.ResponseRecorder {
	return requestPublicWriteAtRoute(router, method, "/resources", hash, path, extra, body)
}

func requestPublicWriteAtRoute(router http.Handler, method, route, hash, path string, extra url.Values, body io.Reader) *httptest.ResponseRecorder {
	query := url.Values{
		"hash": {hash},
		"path": {path},
	}
	for key, values := range extra {
		query[key] = values
	}
	request := httptest.NewRequest(method, "/public/api"+route+"?"+query.Encode(), body)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func marshalPublicWriteBody(t *testing.T, value any) io.Reader {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(payload)
}
