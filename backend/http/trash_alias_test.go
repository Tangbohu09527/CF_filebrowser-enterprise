package http

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/files"
	commonerrors "github.com/gtsteffaniak/filebrowser/backend/common/errors"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
)

func TestTrashAliasCannotCreateReservedEntries(t *testing.T) {
	source, user, id := createTrashFixture(t)
	user.Permissions.Modify = true
	status, body := callTrash(t, user, trashPostHandler, http.MethodPost, "/api/trash", "", trashRequest{Source: "source1", Path: "/public/sample.txt", OperationID: id})
	if status != http.StatusOK {
		t.Fatalf("trash fixture: %d %s", status, body)
	}
	if err := os.Symlink(filepath.Join(source, utils.TrashDirectory), filepath.Join(source, "trash-alias")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("Windows symlink privilege unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(source, "public"), filepath.Join(source, "normal-alias")); err != nil {
		t.Fatal(err)
	}
	config.Auth.Key = "synthetic-trash-alias-upload-key"
	if err := store.Settings.Save(config); err != nil {
		t.Fatal(err)
	}
	names := func() []string {
		entries, err := os.ReadDir(filepath.Join(source, utils.TrashDirectory))
		if err != nil {
			t.Fatal(err)
		}
		result := []string{}
		for _, entry := range entries {
			result = append(result, entry.Name())
		}
		return result
	}
	before := names()
	cases := []struct {
		name, method, path string
		handler            handleFunc
		directory, chunk   bool
	}{
		{"PUT file", http.MethodPut, "/trash-alias/new-put.txt", resourcePutHandler, false, false},
		{"POST file", http.MethodPost, "/trash-alias/new-post.txt", resourcePostHandler, false, false},
		{"POST directory", http.MethodPost, "/trash-alias/new-directory", resourcePostHandler, true, false},
		{"POST chunk", http.MethodPost, "/trash-alias/new-chunk.txt", resourcePostHandler, false, true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			query := url.Values{"source": {"source1"}, "path": {test.path}}
			if test.directory {
				query.Set("isDir", "true")
			}
			r := httptest.NewRequest(test.method, "/api/resources?"+query.Encode(), strings.NewReader("DATA"))
			if test.chunk {
				r.Header.Set("X-File-Chunk-Offset", "0")
				r.Header.Set("X-File-Total-Size", "4")
			}
			w := httptest.NewRecorder()
			status, err := test.handler(w, r, &requestContext{user: user})
			if status != http.StatusForbidden {
				t.Fatalf("reserved creation accepted: %d %v", status, err)
			}
			if after := names(); !reflect.DeepEqual(after, before) {
				t.Fatalf("reserved tree changed: before=%v after=%v", before, after)
			}
		})
	}
	if err := files.WriteFile("source1", "/trash-alias/direct-file.txt", strings.NewReader("DATA")); err != commonerrors.ErrAccessDenied {
		t.Fatalf("direct WriteFile ignored denial: %v", err)
	}
	if err := files.WriteDirectory(utils.FileOptions{Source: "source1", Path: "/trash-alias/direct-directory"}); err != commonerrors.ErrAccessDenied {
		t.Fatalf("direct WriteDirectory ignored denial: %v", err)
	}
	if after := names(); !reflect.DeepEqual(after, before) {
		t.Fatalf("direct helper changed reserved tree: %v", after)
	}
	// Legitimate missing leaves remain writable, including ordinary aliases.
	for _, target := range []string{"/public/normal-new.txt", "/normal-alias/normal-alias-new.txt"} {
		r := httptest.NewRequest(http.MethodPut, "/api/resources?"+url.Values{"source": {"source1"}, "path": {target}}.Encode(), strings.NewReader("NORMAL"))
		status, err := resourcePutHandler(httptest.NewRecorder(), r, &requestContext{user: user})
		if status != http.StatusOK {
			t.Fatalf("ordinary creation blocked: %s %d %v", target, status, err)
		}
	}
}
