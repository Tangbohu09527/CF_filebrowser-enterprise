package http

import (
	"net/http"
	"testing"
)

func TestAuthenticatedPreviewWithoutServerPreviewReturnsBadRequest(t *testing.T) {
	fixture := setupPreviewSecurityFixture(t)
	file := fixture.writeFile(t, "no-server-preview.bin", []byte{0, 1, 2, 3, 4, 5, 6, 7})
	user := fixture.user(t, true, true, false)
	if user.Permissions.Admin || !user.Permissions.Browse || !user.Permissions.Preview || user.Permissions.Download {
		t.Fatal("fixture must be an ordinary user with Browse and Preview only")
	}
	if info := fixture.fileInfo(t, user, file); info.HasPreview {
		t.Fatal("fixture unexpectedly advertises a server preview")
	}

	// The existing request helper invokes previewHandler, including its error
	// mapping after previewHelperFunc returns the unsupported-file response.
	response := fixture.previewRequest(t, user, file, "small", 0)
	if response.status != http.StatusBadRequest || response.err == nil || len(response.body) != 0 {
		t.Fatalf("unsupported authenticated preview: status=%d bytes=%d err=%v",
			response.status, len(response.body), response.err)
	}
}
