package http

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

type archivePermissionZipEntry struct {
	name         string
	content      string
	mode         fs.FileMode
	tarType      byte
	forceTarType bool
	linkName     string
	store        bool
}

func TestArchivePermissionSecurity_OperationSpecificPermissions(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)

	t.Run("new target with Create succeeds", func(t *testing.T) {
		source := writeArchivePermissionFile(t, sourcePath, "archive-new-create.txt", "new create source")
		destination := filepath.Join(sourcePath, "public", "archive-new-create.zip")
		user := archivePermissionUser(sourcePath, "archive-new-create-user", users.Permissions{
			Create: true, Browse: true, Download: true,
		})

		status, err := requestArchivePermissionCreate(t, user, "/public/"+filepath.Base(source), "/public/"+filepath.Base(destination), false)
		requireArchivePermissionStatus(t, status, err, http.StatusOK)
		assertArchivePermissionZipContains(t, destination, filepath.Base(source))
	})

	t.Run("new target without Create is denied without writes", func(t *testing.T) {
		source := writeArchivePermissionFile(t, sourcePath, "archive-no-create.txt", "no create source")
		destination := filepath.Join(sourcePath, "public", "archive-no-create.zip")
		before := archivePermissionDirectoryNames(t, filepath.Dir(destination))
		user := archivePermissionUser(sourcePath, "archive-no-create-user", users.Permissions{
			Browse: true, Download: true,
		})

		status, err := requestArchivePermissionCreate(t, user, "/public/"+filepath.Base(source), "/public/"+filepath.Base(destination), false)
		requireArchivePermissionStatus(t, status, err, http.StatusForbidden)
		assertArchivePermissionAbsent(t, destination)
		assertArchivePermissionDirectoryNames(t, filepath.Dir(destination), before)
	})

	t.Run("existing target with Modify succeeds", func(t *testing.T) {
		source := writeArchivePermissionFile(t, sourcePath, "archive-existing-modify.txt", "modify source")
		destination := writeArchivePermissionFile(t, sourcePath, "archive-existing-modify.zip", "original archive")
		user := archivePermissionUser(sourcePath, "archive-existing-modify-user", users.Permissions{
			Modify: true, Browse: true, Download: true,
		})

		status, err := requestArchivePermissionCreate(t, user, "/public/"+filepath.Base(source), "/public/"+filepath.Base(destination), false)
		requireArchivePermissionStatus(t, status, err, http.StatusOK)
		assertArchivePermissionZipContains(t, destination, filepath.Base(source))
	})

	t.Run("existing target with only Create is denied without truncation", func(t *testing.T) {
		source := writeArchivePermissionFile(t, sourcePath, "archive-existing-create-only.txt", "create-only source")
		destination := writeArchivePermissionFile(t, sourcePath, "archive-existing-create-only.zip", "original archive remains")
		user := archivePermissionUser(sourcePath, "archive-existing-create-only-user", users.Permissions{
			Create: true, Browse: true, Download: true,
		})

		status, err := requestArchivePermissionCreate(t, user, "/public/"+filepath.Base(source), "/public/"+filepath.Base(destination), false)
		requireArchivePermissionStatus(t, status, err, http.StatusForbidden)
		assertArchivePermissionContent(t, destination, "original archive remains")
	})

	t.Run("deleteAfter with Delete succeeds", func(t *testing.T) {
		source := writeArchivePermissionFile(t, sourcePath, "archive-delete-allowed.txt", "delete allowed source")
		destination := filepath.Join(sourcePath, "public", "archive-delete-allowed.zip")
		user := archivePermissionUser(sourcePath, "archive-delete-allowed-user", users.Permissions{
			Create: true, Delete: true, Browse: true, Download: true,
		})

		status, err := requestArchivePermissionCreate(t, user, "/public/"+filepath.Base(source), "/public/"+filepath.Base(destination), true)
		requireArchivePermissionStatus(t, status, err, http.StatusOK)
		assertArchivePermissionZipContains(t, destination, filepath.Base(source))
		assertArchivePermissionAbsent(t, source)
	})

	t.Run("deleteAfter without Delete is denied before archive creation", func(t *testing.T) {
		source := writeArchivePermissionFile(t, sourcePath, "archive-delete-denied.txt", "delete denied source")
		destination := filepath.Join(sourcePath, "public", "archive-delete-denied.zip")
		before := archivePermissionDirectoryNames(t, filepath.Dir(destination))
		user := archivePermissionUser(sourcePath, "archive-delete-denied-user", users.Permissions{
			Create: true, Browse: true, Download: true,
		})

		status, err := requestArchivePermissionCreate(t, user, "/public/"+filepath.Base(source), "/public/"+filepath.Base(destination), true)
		requireArchivePermissionStatus(t, status, err, http.StatusForbidden)
		assertArchivePermissionContent(t, source, "delete denied source")
		assertArchivePermissionAbsent(t, destination)
		assertArchivePermissionDirectoryNames(t, filepath.Dir(destination), before)
	})
}

func TestArchivePermissionSecurity_DeleteAfterRejectsDeniedDescendantBeforeWrite(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)
	sourceDirectory := filepath.Join(sourcePath, "public", "archive-delete-acl")
	if err := os.Mkdir(sourceDirectory, 0755); err != nil {
		t.Fatal(err)
	}
	allowed := filepath.Join(sourceDirectory, "allowed.txt")
	denied := filepath.Join(sourceDirectory, "denied.txt")
	writeArchivePermissionPath(t, allowed, "allowed source remains")
	writeArchivePermissionPath(t, denied, "denied source remains")
	destination := writeArchivePermissionFile(t, sourcePath, "archive-delete-acl.zip", "original archive remains")
	username := "archive-delete-acl-user"
	user := archivePermissionUser(sourcePath, username, users.Permissions{
		Modify: true, Delete: true, Browse: true, Download: true,
	})
	savePermissionReadUser(t, user)
	if err := store.Access.DenyUser(sourcePath, "/public/archive-delete-acl/denied.txt", username); err != nil {
		t.Fatal(err)
	}

	status, err := requestArchivePermissionCreate(t, user, "/public/archive-delete-acl", "/public/archive-delete-acl.zip", true)
	requireArchivePermissionStatus(t, status, err, http.StatusForbidden)
	assertArchivePermissionContent(t, destination, "original archive remains")
	assertArchivePermissionContent(t, allowed, "allowed source remains")
	assertArchivePermissionContent(t, denied, "denied source remains")
}

func TestArchivePermissionSecurity_DeleteAfterRejectsSymlinkSource(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)
	target := writeArchivePermissionFile(t, sourcePath, "archive-delete-link-target.txt", "target remains")
	link := filepath.Join(sourcePath, "public", "archive-delete-link.txt")
	if err := os.Symlink(filepath.Base(target), link); err != nil {
		t.Skipf("symlink assertions unavailable: %v", err)
	}
	destination := filepath.Join(sourcePath, "public", "archive-delete-link.zip")
	user := archivePermissionUser(sourcePath, "archive-delete-link-user", users.Permissions{
		Create: true, Delete: true, Browse: true, Download: true,
	})

	status, err := requestArchivePermissionCreate(t, user, "/public/archive-delete-link.txt", "/public/archive-delete-link.zip", true)
	requireArchivePermissionStatus(t, status, err, http.StatusForbidden)
	assertArchivePermissionAbsent(t, destination)
	assertArchivePermissionContent(t, target, "target remains")
	if info, statErr := os.Lstat(link); statErr != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("source symlink changed: info=%v err=%v", info, statErr)
	}
}

func TestExtractPermissionSecurity_OperationSpecificPermissions(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)

	t.Run("new target with Create succeeds", func(t *testing.T) {
		archivePath := writeArchivePermissionZip(t, sourcePath, "extract-new-create.zip", []archivePermissionZipEntry{
			{name: "new.txt", content: "new extract content", mode: 0644},
		})
		destination := makeArchivePermissionDestination(t, sourcePath, "extract-new-create")
		user := archivePermissionUser(sourcePath, "extract-new-create-user", users.Permissions{Create: true})

		status, err := requestArchivePermissionExtract(t, user, archivePath, destination, false)
		requireArchivePermissionStatus(t, status, err, http.StatusOK)
		assertArchivePermissionContent(t, filepath.Join(destination, "new.txt"), "new extract content")
	})

	t.Run("new target without Create is denied without writes", func(t *testing.T) {
		archivePath := writeArchivePermissionZip(t, sourcePath, "extract-no-create.zip", []archivePermissionZipEntry{
			{name: "new.txt", content: "must not be extracted", mode: 0644},
		})
		destination := makeArchivePermissionDestination(t, sourcePath, "extract-no-create")
		user := archivePermissionUser(sourcePath, "extract-no-create-user", users.Permissions{})

		status, err := requestArchivePermissionExtract(t, user, archivePath, destination, false)
		requireArchivePermissionStatus(t, status, err, http.StatusForbidden)
		assertArchivePermissionAbsent(t, filepath.Join(destination, "new.txt"))
	})

	t.Run("existing target with Modify succeeds", func(t *testing.T) {
		archivePath := writeArchivePermissionZip(t, sourcePath, "extract-existing-modify.zip", []archivePermissionZipEntry{
			{name: "existing.txt", content: "modified extract content", mode: 0644},
		})
		destination := makeArchivePermissionDestination(t, sourcePath, "extract-existing-modify")
		existing := filepath.Join(destination, "existing.txt")
		writeArchivePermissionPath(t, existing, "original extract content")
		user := archivePermissionUser(sourcePath, "extract-existing-modify-user", users.Permissions{Modify: true})

		status, err := requestArchivePermissionExtract(t, user, archivePath, destination, false)
		requireArchivePermissionStatus(t, status, err, http.StatusOK)
		assertArchivePermissionContent(t, existing, "modified extract content")
	})

	t.Run("existing target with only Create is denied before any entry is written", func(t *testing.T) {
		archivePath := writeArchivePermissionZip(t, sourcePath, "extract-existing-create-only.zip", []archivePermissionZipEntry{
			{name: "a-new.txt", content: "partial write", mode: 0644},
			{name: "z-existing.txt", content: "unauthorized overwrite", mode: 0644},
		})
		destination := makeArchivePermissionDestination(t, sourcePath, "extract-existing-create-only")
		existing := filepath.Join(destination, "z-existing.txt")
		writeArchivePermissionPath(t, existing, "original extract content remains")
		user := archivePermissionUser(sourcePath, "extract-existing-create-only-user", users.Permissions{Create: true})

		status, err := requestArchivePermissionExtract(t, user, archivePath, destination, false)
		requireArchivePermissionStatus(t, status, err, http.StatusForbidden)
		assertArchivePermissionContent(t, existing, "original extract content remains")
		assertArchivePermissionAbsent(t, filepath.Join(destination, "a-new.txt"))
	})

	t.Run("deleteAfter with Delete succeeds", func(t *testing.T) {
		archivePath := writeArchivePermissionZip(t, sourcePath, "extract-delete-allowed.zip", []archivePermissionZipEntry{
			{name: "new.txt", content: "delete allowed extract", mode: 0644},
		})
		destination := makeArchivePermissionDestination(t, sourcePath, "extract-delete-allowed")
		user := archivePermissionUser(sourcePath, "extract-delete-allowed-user", users.Permissions{Create: true, Delete: true})

		status, err := requestArchivePermissionExtract(t, user, archivePath, destination, true)
		requireArchivePermissionStatus(t, status, err, http.StatusOK)
		assertArchivePermissionContent(t, filepath.Join(destination, "new.txt"), "delete allowed extract")
		assertArchivePermissionAbsent(t, archivePath)
	})

	t.Run("deleteAfter without Delete is denied before extraction", func(t *testing.T) {
		archivePath := writeArchivePermissionZip(t, sourcePath, "extract-delete-denied.zip", []archivePermissionZipEntry{
			{name: "new.txt", content: "must not be extracted", mode: 0644},
		})
		destination := makeArchivePermissionDestination(t, sourcePath, "extract-delete-denied")
		user := archivePermissionUser(sourcePath, "extract-delete-denied-user", users.Permissions{Create: true})

		status, err := requestArchivePermissionExtract(t, user, archivePath, destination, true)
		requireArchivePermissionStatus(t, status, err, http.StatusForbidden)
		if _, statErr := os.Stat(archivePath); statErr != nil {
			t.Fatalf("source archive changed after denied deleteAfter: %v", statErr)
		}
		assertArchivePermissionAbsent(t, filepath.Join(destination, "new.txt"))
	})
}

func TestExtractPermissionSecurity_PreflightRejectsConflictsAndDeniedPaths(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)

	t.Run("directory to file type conflict leaves earlier entry untouched", func(t *testing.T) {
		archivePath := writeArchivePermissionZip(t, sourcePath, "extract-type-conflict.zip", []archivePermissionZipEntry{
			{name: "a-safe.txt", content: "must not be written", mode: 0644},
			{name: "z-conflict", content: "must not replace directory", mode: 0644},
		})
		destination := makeArchivePermissionDestination(t, sourcePath, "extract-type-conflict")
		conflict := filepath.Join(destination, "z-conflict")
		if err := os.Mkdir(conflict, 0755); err != nil {
			t.Fatal(err)
		}
		user := archivePermissionUser(sourcePath, "extract-type-conflict-user", users.Permissions{Create: true, Modify: true})

		status, err := requestArchivePermissionExtract(t, user, archivePath, destination, false)
		requireArchivePermissionStatus(t, status, err, http.StatusConflict)
		assertArchivePermissionAbsent(t, filepath.Join(destination, "a-safe.txt"))
		if info, statErr := os.Stat(conflict); statErr != nil || !info.IsDir() {
			t.Fatalf("conflicting directory changed: info=%v err=%v", info, statErr)
		}
	})

	t.Run("file to directory type conflict leaves earlier entry untouched", func(t *testing.T) {
		archivePath := writeArchivePermissionZip(t, sourcePath, "extract-directory-conflict.zip", []archivePermissionZipEntry{
			{name: "a-safe.txt", content: "must not be written", mode: 0644},
			{name: "z-conflict", mode: fs.ModeDir | 0755},
		})
		destination := makeArchivePermissionDestination(t, sourcePath, "extract-directory-conflict")
		conflict := filepath.Join(destination, "z-conflict")
		writeArchivePermissionPath(t, conflict, "regular file remains")
		user := archivePermissionUser(sourcePath, "extract-directory-conflict-user", users.Permissions{Create: true, Modify: true})

		status, err := requestArchivePermissionExtract(t, user, archivePath, destination, false)
		requireArchivePermissionStatus(t, status, err, http.StatusConflict)
		assertArchivePermissionAbsent(t, filepath.Join(destination, "a-safe.txt"))
		assertArchivePermissionContent(t, conflict, "regular file remains")
	})

	t.Run("entry ACL denial rejects every entry before extraction", func(t *testing.T) {
		archivePath := writeArchivePermissionZip(t, sourcePath, "extract-acl-denied.zip", []archivePermissionZipEntry{
			{name: "a-allowed.txt", content: "must not be partially written", mode: 0644},
			{name: "blocked.txt", content: "ACL denied", mode: 0644},
		})
		destination := makeArchivePermissionDestination(t, sourcePath, "extract-acl-denied")
		username := "extract-acl-denied-user"
		user := archivePermissionUser(sourcePath, username, users.Permissions{Create: true})
		savePermissionReadUser(t, user)
		if err := store.Access.DenyUser(sourcePath, "/public/extract-acl-denied/blocked.txt", username); err != nil {
			t.Fatal(err)
		}

		status, err := requestArchivePermissionExtract(t, user, archivePath, destination, false)
		requireArchivePermissionStatus(t, status, err, http.StatusForbidden)
		assertArchivePermissionAbsent(t, filepath.Join(destination, "a-allowed.txt"))
		assertArchivePermissionAbsent(t, filepath.Join(destination, "blocked.txt"))
	})

	t.Run("path traversal is rejected before extraction", func(t *testing.T) {
		archivePath := writeArchivePermissionZip(t, sourcePath, "extract-traversal.zip", []archivePermissionZipEntry{
			{name: "../escaped.txt", content: "escaped", mode: 0644},
		})
		destination := makeArchivePermissionDestination(t, sourcePath, "extract-traversal")
		escaped := filepath.Join(filepath.Dir(destination), "escaped.txt")
		user := archivePermissionUser(sourcePath, "extract-traversal-user", users.Permissions{Create: true})

		status, err := requestArchivePermissionExtract(t, user, archivePath, destination, false)
		if status == http.StatusOK || err == nil {
			t.Fatalf("path traversal status: got %d with err=%v, want rejection", status, err)
		}
		assertArchivePermissionAbsent(t, escaped)
	})

	t.Run("symlink ancestor conflict cannot redirect extraction", func(t *testing.T) {
		archivePath := writeArchivePermissionZip(t, sourcePath, "extract-symlink-conflict.zip", []archivePermissionZipEntry{
			{name: "redirect/escaped.txt", content: "escaped through symlink", mode: 0644},
		})
		destination := makeArchivePermissionDestination(t, sourcePath, "extract-symlink-conflict")
		outside := t.TempDir()
		link := filepath.Join(destination, "redirect")
		if err := os.Symlink(outside, link); err != nil {
			t.Skipf("symlink assertions unavailable: %v", err)
		}
		user := archivePermissionUser(sourcePath, "extract-symlink-conflict-user", users.Permissions{Create: true, Modify: true})

		status, err := requestArchivePermissionExtract(t, user, archivePath, destination, false)
		requireArchivePermissionStatus(t, status, err, http.StatusConflict)
		assertArchivePermissionAbsent(t, filepath.Join(outside, "escaped.txt"))
		if info, lstatErr := os.Lstat(link); lstatErr != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("symlink conflict changed: info=%v err=%v", info, lstatErr)
		}
	})
}

func TestExtractPermissionSecurity_PreflightRejectsArchivePlanConflicts(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)
	tests := []struct {
		name    string
		entries []archivePermissionZipEntry
	}{
		{
			name: "exact duplicate file",
			entries: []archivePermissionZipEntry{
				{name: "duplicate.txt", content: "first", mode: 0644},
				{name: "duplicate.txt", content: "second", mode: 0644},
			},
		},
		{
			name: "cleaned path collision",
			entries: []archivePermissionZipEntry{
				{name: "folder/item.txt", content: "first", mode: 0644},
				{name: "folder/./item.txt", content: "second", mode: 0644},
			},
		},
		{
			name: "portable case collision",
			entries: []archivePermissionZipEntry{
				{name: "Case.txt", content: "upper", mode: 0644},
				{name: "case.txt", content: "lower", mode: 0644},
			},
		},
		{
			name: "file used as later directory ancestor",
			entries: []archivePermissionZipEntry{
				{name: "prefix", content: "file", mode: 0644},
				{name: "prefix/child.txt", content: "child", mode: 0644},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			archiveName := "extract-plan-" + strings.ReplaceAll(test.name, " ", "-") + ".zip"
			archivePath := writeArchivePermissionZip(t, sourcePath, archiveName, test.entries)
			destination := makeArchivePermissionDestination(t, sourcePath, strings.TrimSuffix(archiveName, ".zip"))
			user := archivePermissionUser(sourcePath, archiveName+"-user", users.Permissions{Create: true, Modify: true})

			status, err := requestArchivePermissionExtract(t, user, archivePath, destination, false)
			requireArchivePermissionStatus(t, status, err, http.StatusConflict)
			assertArchivePermissionDirectoryNames(t, destination, nil)
		})
	}
}

func TestExtractPermissionSecurity_PlannedDirectoriesUseCreateWithoutModify(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)

	t.Run("new explicit directory followed by child", func(t *testing.T) {
		archivePath := writeArchivePermissionZip(t, sourcePath, "extract-planned-directory.zip", []archivePermissionZipEntry{
			{name: "planned", mode: fs.ModeDir | 0755},
			{name: "planned/child.txt", content: "planned child", mode: 0644},
		})
		destination := makeArchivePermissionDestination(t, sourcePath, "extract-planned-directory")
		user := archivePermissionUser(sourcePath, "extract-planned-directory-user", users.Permissions{Create: true})

		status, err := requestArchivePermissionExtract(t, user, archivePath, destination, false)
		requireArchivePermissionStatus(t, status, err, http.StatusOK)
		assertArchivePermissionContent(t, filepath.Join(destination, "planned", "child.txt"), "planned child")
	})

	t.Run("existing implicit directory only contains new child", func(t *testing.T) {
		archivePath := writeArchivePermissionZip(t, sourcePath, "extract-existing-container.zip", []archivePermissionZipEntry{
			{name: "existing/new.txt", content: "new child", mode: 0644},
		})
		destination := makeArchivePermissionDestination(t, sourcePath, "extract-existing-container")
		if err := os.Mkdir(filepath.Join(destination, "existing"), 0755); err != nil {
			t.Fatal(err)
		}
		user := archivePermissionUser(sourcePath, "extract-existing-container-user", users.Permissions{Create: true})

		status, err := requestArchivePermissionExtract(t, user, archivePath, destination, false)
		requireArchivePermissionStatus(t, status, err, http.StatusOK)
		assertArchivePermissionContent(t, filepath.Join(destination, "existing", "new.txt"), "new child")
	})
}

func TestExtractPermissionSecurity_RejectsUnsupportedSpecialEntries(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)

	t.Run("ZIP named pipe", func(t *testing.T) {
		archivePath := writeArchivePermissionZip(t, sourcePath, "extract-zip-pipe.zip", []archivePermissionZipEntry{
			{name: "safe.txt", content: "must not be written", mode: 0644},
			{name: "pipe", mode: fs.ModeNamedPipe | 0600},
		})
		destination := makeArchivePermissionDestination(t, sourcePath, "extract-zip-pipe")
		user := archivePermissionUser(sourcePath, "extract-zip-pipe-user", users.Permissions{Create: true})

		status, err := requestArchivePermissionExtract(t, user, archivePath, destination, false)
		requireArchivePermissionStatus(t, status, err, http.StatusConflict)
		assertArchivePermissionDirectoryNames(t, destination, nil)
	})

	tarTypes := []struct {
		name     string
		typeflag byte
		linkName string
	}{
		{name: "hardlink", typeflag: tar.TypeLink, linkName: "target.txt"},
		{name: "FIFO", typeflag: tar.TypeFifo},
		{name: "block device", typeflag: tar.TypeBlock},
		{name: "character device", typeflag: tar.TypeChar},
	}
	for _, test := range tarTypes {
		t.Run("TAR "+test.name, func(t *testing.T) {
			archiveName := "extract-tar-" + strings.ReplaceAll(strings.ToLower(test.name), " ", "-") + ".tar.gz"
			archivePath := writeArchivePermissionTarGz(t, sourcePath, archiveName, []archivePermissionZipEntry{
				{name: "safe.txt", content: "must not be written", mode: 0644},
				{name: "special", mode: 0600, tarType: test.typeflag, forceTarType: true, linkName: test.linkName},
			})
			destination := makeArchivePermissionDestination(t, sourcePath, strings.TrimSuffix(archiveName, ".tar.gz"))
			user := archivePermissionUser(sourcePath, archiveName+"-user", users.Permissions{Create: true})

			status, err := requestArchivePermissionExtract(t, user, archivePath, destination, false)
			requireArchivePermissionStatus(t, status, err, http.StatusConflict)
			assertArchivePermissionDirectoryNames(t, destination, nil)
		})
	}
}

func TestExtractPermissionSecurity_SymlinkTargetsAreBoundedAndCannotTraverseExistingLinks(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)

	t.Run("oversized ZIP symlink target is rejected before writes", func(t *testing.T) {
		archivePath := writeArchivePermissionZip(t, sourcePath, "extract-oversized-symlink.zip", []archivePermissionZipEntry{
			{name: "a-safe.txt", content: "must not be written", mode: 0644},
			{name: "z-link", content: strings.Repeat("a", 4097), mode: fs.ModeSymlink | 0777},
		})
		destination := makeArchivePermissionDestination(t, sourcePath, "extract-oversized-symlink")
		user := archivePermissionUser(sourcePath, "extract-oversized-symlink-user", users.Permissions{Create: true})

		status, err := requestArchivePermissionExtract(t, user, archivePath, destination, false)
		requireArchivePermissionStatus(t, status, err, http.StatusConflict)
		assertArchivePermissionDirectoryNames(t, destination, nil)
	})

	t.Run("target through existing symlink is rejected", func(t *testing.T) {
		archivePath := writeArchivePermissionZip(t, sourcePath, "extract-target-through-symlink.zip", []archivePermissionZipEntry{
			{name: "link", content: "redirect/outside.txt", mode: fs.ModeSymlink | 0777},
		})
		destination := makeArchivePermissionDestination(t, sourcePath, "extract-target-through-symlink")
		outside := t.TempDir()
		if err := os.Symlink(outside, filepath.Join(destination, "redirect")); err != nil {
			t.Skipf("symlink assertions unavailable: %v", err)
		}
		user := archivePermissionUser(sourcePath, "extract-target-through-symlink-user", users.Permissions{Create: true})

		status, err := requestArchivePermissionExtract(t, user, archivePath, destination, false)
		requireArchivePermissionStatus(t, status, err, http.StatusConflict)
		assertArchivePermissionAbsent(t, filepath.Join(destination, "link"))
		assertArchivePermissionAbsent(t, filepath.Join(outside, "outside.txt"))
	})
}

func TestExtractPermissionSecurity_DeleteAfterRejectsSymlinkArchive(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)
	archivePath := writeArchivePermissionZip(t, sourcePath, "extract-delete-link-target.zip", []archivePermissionZipEntry{
		{name: "new.txt", content: "must not be extracted", mode: 0644},
	})
	link := filepath.Join(sourcePath, "public", "extract-delete-link.zip")
	if err := os.Symlink(filepath.Base(archivePath), link); err != nil {
		t.Skipf("symlink assertions unavailable: %v", err)
	}
	destination := makeArchivePermissionDestination(t, sourcePath, "extract-delete-link")
	user := archivePermissionUser(sourcePath, "extract-delete-link-user", users.Permissions{Create: true, Delete: true})

	status, err := requestArchivePermissionExtract(t, user, link, destination, true)
	requireArchivePermissionStatus(t, status, err, http.StatusForbidden)
	assertArchivePermissionAbsent(t, filepath.Join(destination, "new.txt"))
	if _, statErr := os.Stat(archivePath); statErr != nil {
		t.Fatalf("source archive changed: %v", statErr)
	}
	if info, statErr := os.Lstat(link); statErr != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("source archive symlink changed: info=%v err=%v", info, statErr)
	}
}

func TestExtractPermissionSecurity_TarLegacyRegularFileUsesPreflight(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)
	archivePath := writeArchivePermissionTarGz(t, sourcePath, "extract-legacy-regular.tgz", []archivePermissionZipEntry{
		{name: "legacy.txt", content: "legacy regular content", mode: 0644, tarType: tar.TypeRegA, forceTarType: true},
	})
	destination := makeArchivePermissionDestination(t, sourcePath, "extract-legacy-regular")
	user := archivePermissionUser(sourcePath, "extract-legacy-regular-user", users.Permissions{Create: true})

	status, err := requestArchivePermissionExtract(t, user, archivePath, destination, false)
	requireArchivePermissionStatus(t, status, err, http.StatusOK)
	assertArchivePermissionContent(t, filepath.Join(destination, "legacy.txt"), "legacy regular content")
}

func TestExtractPermissionSecurity_FailedOverwritePreservesOriginalAndCleansTemporaryFile(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)
	archivePath := writeArchivePermissionZip(t, sourcePath, "extract-corrupt-overwrite.zip", []archivePermissionZipEntry{
		{name: "existing.txt", content: "corrupt replacement", mode: 0644, store: true},
	})
	corruptArchivePermissionFirstZipEntry(t, archivePath)
	destination := makeArchivePermissionDestination(t, sourcePath, "extract-corrupt-overwrite")
	existing := filepath.Join(destination, "existing.txt")
	writeArchivePermissionPath(t, existing, "original extract content remains")
	user := archivePermissionUser(sourcePath, "extract-corrupt-overwrite-user", users.Permissions{Modify: true})

	status, err := requestArchivePermissionExtract(t, user, archivePath, destination, false)
	requireArchivePermissionStatus(t, status, err, http.StatusInternalServerError)
	assertArchivePermissionContent(t, existing, "original extract content remains")
	assertArchivePermissionDirectoryNames(t, destination, []string{"existing.txt"})
}

func TestExtractPermissionSecurity_OverwriteBreaksExistingHardlink(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)
	archivePath := writeArchivePermissionZip(t, sourcePath, "extract-hardlink-overwrite.zip", []archivePermissionZipEntry{
		{name: "existing.txt", content: "replacement content", mode: 0644},
	})
	destination := makeArchivePermissionDestination(t, sourcePath, "extract-hardlink-overwrite")
	externalDirectory := t.TempDir()
	external := filepath.Join(externalDirectory, "external.txt")
	writeArchivePermissionPath(t, external, "external content remains")
	existing := filepath.Join(destination, "existing.txt")
	if err := os.Link(external, existing); err != nil {
		t.Skipf("hardlink assertions unavailable: %v", err)
	}
	user := archivePermissionUser(sourcePath, "extract-hardlink-overwrite-user", users.Permissions{Modify: true})

	status, err := requestArchivePermissionExtract(t, user, archivePath, destination, false)
	requireArchivePermissionStatus(t, status, err, http.StatusOK)
	assertArchivePermissionContent(t, existing, "replacement content")
	assertArchivePermissionContent(t, external, "external content remains")
}

func TestExtractPermissionSecurity_TarGzPreflightPreventsPartialWrites(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)
	archivePath := writeArchivePermissionTarGz(t, sourcePath, "extract-permission.tar.gz", []archivePermissionZipEntry{
		{name: "a-new.txt", content: "must not be partially written", mode: 0644},
		{name: "z-existing.txt", content: "unauthorized overwrite", mode: 0644},
	})
	destination := makeArchivePermissionDestination(t, sourcePath, "extract-tar-permission")
	existing := filepath.Join(destination, "z-existing.txt")
	writeArchivePermissionPath(t, existing, "original tar target remains")
	user := archivePermissionUser(sourcePath, "extract-tar-permission-user", users.Permissions{Create: true})

	status, err := requestArchivePermissionExtract(t, user, archivePath, destination, false)
	requireArchivePermissionStatus(t, status, err, http.StatusForbidden)
	assertArchivePermissionContent(t, existing, "original tar target remains")
	assertArchivePermissionAbsent(t, filepath.Join(destination, "a-new.txt"))
}

func TestArchivePermissionSecurity_APITokenCapabilityIntersection(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)
	configurePermissionReadAuth(t)

	source := writeArchivePermissionFile(t, sourcePath, "archive-token-source.txt", "token archive source")
	destination := writeArchivePermissionFile(t, sourcePath, "archive-token-existing.zip", "token original archive remains")
	user := archivePermissionUser(sourcePath, "archive-token-user", users.Permissions{
		Api: true, Create: true, Modify: true, Browse: true, Download: true,
	})
	savePermissionReadUser(t, user)
	token := issuePermissionReadAPIToken(t, user, "archive-token-without-modify", users.Permissions{
		Api: true, Create: true, Browse: true, Download: true,
	})

	requestBody, err := json.Marshal(archiveCreateRequest{
		FromSource:  "source1",
		Paths:       []string{"/public/" + filepath.Base(source)},
		Destination: "/public/" + filepath.Base(destination),
		Format:      "zip",
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/resources/archive", bytes.NewReader(requestBody))
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	api := http.NewServeMux()
	api.HandleFunc("POST /resources/archive", withUser(archiveCreateHandler))
	router := http.NewServeMux()
	router.Handle("/api/", http.StripPrefix("/api", api))

	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("archive API token status: got %d, want %d (body: %q)", recorder.Code, http.StatusForbidden, recorder.Body.String())
	}
	assertArchivePermissionContent(t, destination, "token original archive remains")
}

func archivePermissionUser(sourcePath, username string, permissions users.Permissions) *users.User {
	return &users.User{
		Username:    username,
		Permissions: permissions,
		Scopes: []users.SourceScope{
			{Name: sourcePath, Scope: "/"},
		},
	}
}

func requestArchivePermissionCreate(t *testing.T, user *users.User, source, destination string, deleteAfter bool) (int, error) {
	t.Helper()
	body, err := json.Marshal(archiveCreateRequest{
		FromSource:  "source1",
		Paths:       []string{source},
		Destination: destination,
		Format:      "zip",
		DeleteAfter: deleteAfter,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/resources/archive", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	returned, handlerErr := archiveCreateHandler(recorder, request, &requestContext{user: user})
	return permissionHandlerStatus(returned, recorder), handlerErr
}

func requestArchivePermissionExtract(t *testing.T, user *users.User, archivePath, destination string, deleteAfter bool) (int, error) {
	t.Helper()
	body, err := json.Marshal(unarchiveRequest{
		FromSource:  "source1",
		Path:        "/public/" + filepath.Base(archivePath),
		Destination: "/public/" + filepath.Base(destination),
		DeleteAfter: deleteAfter,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/resources/unarchive", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	returned, handlerErr := unarchiveHandler(recorder, request, &requestContext{user: user})
	return permissionHandlerStatus(returned, recorder), handlerErr
}

func requireArchivePermissionStatus(t *testing.T, got int, err error, want int) {
	t.Helper()
	if got != want {
		t.Fatalf("status: got %d, want %d (err: %v)", got, want, err)
	}
	if want == http.StatusOK && err != nil {
		t.Fatalf("successful request returned error: %v", err)
	}
}

func writeArchivePermissionFile(t *testing.T, sourcePath, name, content string) string {
	t.Helper()
	path := filepath.Join(sourcePath, "public", name)
	writeArchivePermissionPath(t, path, content)
	return path
}

func writeArchivePermissionPath(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func makeArchivePermissionDestination(t *testing.T, sourcePath, name string) string {
	t.Helper()
	destination := filepath.Join(sourcePath, "public", name)
	if err := os.Mkdir(destination, 0755); err != nil {
		t.Fatal(err)
	}
	return destination
}

func writeArchivePermissionZip(t *testing.T, sourcePath, name string, entries []archivePermissionZipEntry) string {
	t.Helper()
	archivePath := filepath.Join(sourcePath, "public", name)
	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
		if entry.store {
			header.Method = zip.Store
		}
		mode := entry.mode
		if mode == 0 {
			mode = 0644
		}
		header.SetMode(mode)
		if mode.IsDir() {
			header.Method = zip.Store
			if !strings.HasSuffix(header.Name, "/") {
				header.Name += "/"
			}
		}
		entryWriter, createErr := writer.CreateHeader(header)
		if createErr != nil {
			_ = writer.Close()
			_ = file.Close()
			t.Fatal(createErr)
		}
		if entry.content != "" {
			if _, writeErr := entryWriter.Write([]byte(entry.content)); writeErr != nil {
				_ = writer.Close()
				_ = file.Close()
				t.Fatal(writeErr)
			}
		}
	}
	if err = writer.Close(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	return archivePath
}

func corruptArchivePermissionFirstZipEntry(t *testing.T, archivePath string) {
	t.Helper()
	data, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 30 || binary.LittleEndian.Uint32(data[:4]) != 0x04034b50 {
		t.Fatal("ZIP local header is unavailable")
	}
	nameLength := int(binary.LittleEndian.Uint16(data[26:28]))
	extraLength := int(binary.LittleEndian.Uint16(data[28:30]))
	contentOffset := 30 + nameLength + extraLength
	if contentOffset >= len(data) {
		t.Fatal("ZIP entry content is unavailable")
	}
	data[contentOffset] ^= 0xff
	if err := os.WriteFile(archivePath, data, 0644); err != nil {
		t.Fatal(err)
	}
}

func writeArchivePermissionTarGz(t *testing.T, sourcePath, name string, entries []archivePermissionZipEntry) string {
	t.Helper()
	archivePath := filepath.Join(sourcePath, "public", name)
	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		mode := entry.mode
		if mode == 0 {
			mode = 0644
		}
		typeflag := byte(tar.TypeReg)
		if mode.IsDir() {
			typeflag = tar.TypeDir
		}
		if entry.forceTarType {
			typeflag = entry.tarType
		}
		size := int64(0)
		if typeflag == tar.TypeReg || typeflag == tar.TypeRegA {
			size = int64(len(entry.content))
		}
		header := &tar.Header{
			Name:     entry.name,
			Mode:     int64(mode.Perm()),
			Size:     size,
			Typeflag: typeflag,
			Linkname: entry.linkName,
		}
		if err = tarWriter.WriteHeader(header); err != nil {
			_ = tarWriter.Close()
			_ = gzipWriter.Close()
			_ = file.Close()
			t.Fatal(err)
		}
		if header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA {
			if _, err = tarWriter.Write([]byte(entry.content)); err != nil {
				_ = tarWriter.Close()
				_ = gzipWriter.Close()
				_ = file.Close()
				t.Fatal(err)
			}
		}
	}
	if err = tarWriter.Close(); err != nil {
		_ = gzipWriter.Close()
		_ = file.Close()
		t.Fatal(err)
	}
	if err = gzipWriter.Close(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	return archivePath
}

func assertArchivePermissionZipContains(t *testing.T, archivePath, name string) {
	t.Helper()
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		t.Fatalf("open resulting archive: %v", err)
	}
	defer reader.Close()
	for _, entry := range reader.File {
		if entry.Name == name {
			return
		}
	}
	t.Fatalf("resulting archive %s does not contain %q", archivePath, name)
}

func assertArchivePermissionContent(t *testing.T, path, want string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(content) != want {
		t.Fatalf("content of %s: got %q, want %q", path, content, want)
	}
}

func assertArchivePermissionAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); err == nil {
		t.Fatalf("expected %s to remain absent", path)
	} else if !os.IsNotExist(err) {
		t.Fatalf("lstat %s: %v", path, err)
	}
}

func archivePermissionDirectoryNames(t *testing.T, path string) []string {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	slices.Sort(names)
	return names
}

func assertArchivePermissionDirectoryNames(t *testing.T, path string, want []string) {
	t.Helper()
	if got := archivePermissionDirectoryNames(t, path); !slices.Equal(got, want) {
		t.Fatalf("directory contents changed after denied request: got %v, want %v", got, want)
	}
}
