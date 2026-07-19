package http

import (
	"bytes"
	"encoding/json"
	"image/color"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fsfiles "github.com/gtsteffaniak/filebrowser/backend/adapters/fs/files"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/access"
	dbshare "github.com/gtsteffaniak/filebrowser/backend/database/share"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/indexing"
	"github.com/gtsteffaniak/filebrowser/backend/indexing/iteminfo"
	"github.com/gtsteffaniak/filebrowser/backend/preview"
)

func TestPublicMediaSecurity(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)
	h := newPermissionShareSecurityHarness(t, sourcePath)

	t.Run("lyrics requires effective Download", func(t *testing.T) {
		audioPath, _ := writePublicLyricsFixture(t, sourcePath, "download-policy", "PUBLIC-LYRICS-DOWNLOAD-POLICY")
		refreshPublicMediaFixture(t)
		owner := h.newOwner(t, "public-lyrics-download-owner", users.Permissions{
			Share: true, Browse: true, Preview: true, Download: true,
		})
		h.saveShare(t, owner, "public-lyrics-download", "/public", func(common *dbshare.CommonShare) {
			common.DisableDownload = true
		})
		response := h.request(http.MethodGet, "/public/api/media/lyrics", url.Values{
			"hash": {"public-lyrics-download"}, "path": {"/" + filepath.Base(audioPath)},
		}, nil, nil)
		assertPermissionShareReadDenied(t, "public lyrics with DisableDownload", response)
	})

	t.Run("single-file share cannot read sibling lyrics", func(t *testing.T) {
		audioPath, _ := writePublicLyricsFixture(t, sourcePath, "single-file", "PUBLIC-LYRICS-SIBLING")
		refreshPublicMediaFixture(t)
		owner := h.newOwner(t, "public-lyrics-single-owner", users.Permissions{
			Share: true, Browse: true, Preview: true, Download: true,
		})
		h.saveShare(t, owner, "public-lyrics-single", "/public/"+filepath.Base(audioPath), nil)
		response := h.request(http.MethodGet, "/public/api/media/lyrics", url.Values{
			"hash": {"public-lyrics-single"}, "path": {"/"},
		}, nil, nil)
		assertPermissionShareReadDenied(t, "single-file sibling lyrics", response)
	})

	t.Run("lyrics sidecar has an independent Access Rule", func(t *testing.T) {
		audioPath, sidecarPath := writePublicLyricsFixture(t, sourcePath, "access-rule", "PUBLIC-LYRICS-ACCESS-RULE")
		refreshPublicMediaFixture(t)
		owner := h.newOwner(t, "public-lyrics-access-owner", users.Permissions{
			Share: true, Browse: true, Preview: true, Download: true,
		})
		h.saveShare(t, owner, "public-lyrics-access", "/public", nil)
		if err := store.Access.DenyUser(sourcePath, "/public/"+filepath.Base(sidecarPath), owner.Username); err != nil {
			t.Fatal(err)
		}
		response := h.request(http.MethodGet, "/public/api/media/lyrics", url.Values{
			"hash": {"public-lyrics-access"}, "path": {"/" + filepath.Base(audioPath)},
		}, nil, nil)
		assertPermissionShareReadDenied(t, "Access Rule denied lyrics", response)
		if strings.Contains(response.Body.String(), "PUBLIC-LYRICS-ACCESS-RULE") {
			t.Fatalf("Access-denied lyrics leaked: %q", response.Body.String())
		}
	})

	t.Run("lyrics sidecar symlink is rejected", func(t *testing.T) {
		audioPath, sidecarPath := writePublicLyricsFixture(t, sourcePath, "symlink", "placeholder")
		outsidePath := filepath.Join(t.TempDir(), "outside.lrc")
		if err := os.WriteFile(outsidePath, []byte("[00:01.00]PUBLIC-LYRICS-SYMLINK\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(sidecarPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outsidePath, sidecarPath); err != nil {
			t.Skipf("symlink fixture is unavailable: %v", err)
		}
		refreshPublicMediaFixture(t)
		owner := h.newOwner(t, "public-lyrics-symlink-owner", users.Permissions{
			Share: true, Browse: true, Preview: true, Download: true,
		})
		h.saveShare(t, owner, "public-lyrics-symlink", "/public", nil)
		response := h.request(http.MethodGet, "/public/api/media/lyrics", url.Values{
			"hash": {"public-lyrics-symlink"}, "path": {"/" + filepath.Base(audioPath)},
		}, nil, nil)
		assertPermissionShareReadDenied(t, "symlink lyrics", response)
		if strings.Contains(response.Body.String(), "PUBLIC-LYRICS-SYMLINK") {
			t.Fatalf("symlink lyrics leaked: %q", response.Body.String())
		}
	})

	t.Run("metadata hides inaccessible sidecar fields", func(t *testing.T) {
		audioPath, sidecarPath := writePublicLyricsFixture(t, sourcePath, "metadata", "PUBLIC-METADATA-LYRICS")
		videoPath := filepath.Join(sourcePath, "public", "metadata-video.mp4")
		subtitlePath := filepath.Join(sourcePath, "public", "metadata-video.srt")
		if err := os.WriteFile(videoPath, []byte("public metadata video"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(subtitlePath, []byte("PUBLIC-METADATA-SUBTITLE"), 0o644); err != nil {
			t.Fatal(err)
		}
		refreshPublicMediaFixture(t)
		owner := h.newOwner(t, "public-metadata-sidecar-owner", users.Permissions{
			Share: true, Browse: true, Preview: true, Download: true,
		})
		h.saveShare(t, owner, "public-metadata-sidecar", "/public", nil)
		for _, deniedPath := range []string{sidecarPath, subtitlePath} {
			indexPath := "/public/" + filepath.Base(deniedPath)
			if err := store.Access.DenyUser(sourcePath, indexPath, owner.Username); err != nil {
				t.Fatal(err)
			}
		}

		audioResponse := h.request(http.MethodGet, "/public/api/media/metadata", url.Values{
			"hash": {"public-metadata-sidecar"}, "path": {"/" + filepath.Base(audioPath)},
		}, nil, nil)
		requirePermissionShareStatus(t, "audio metadata", audioResponse, http.StatusOK)
		var audio iteminfo.ExtendedFileInfo
		if err := json.Unmarshal(audioResponse.Body.Bytes(), &audio); err != nil {
			t.Fatal(err)
		}
		if audio.Metadata != nil && (audio.Metadata.HasLyrics || len(audio.Metadata.Lyrics) != 0) {
			t.Fatalf("metadata exposed denied lyrics sidecar: %+v", audio.Metadata)
		}

		videoResponse := h.request(http.MethodGet, "/public/api/media/metadata", url.Values{
			"hash": {"public-metadata-sidecar"}, "path": {"/" + filepath.Base(videoPath)},
		}, nil, nil)
		requirePermissionShareStatus(t, "video metadata", videoResponse, http.StatusOK)
		var video iteminfo.ExtendedFileInfo
		if err := json.Unmarshal(videoResponse.Body.Bytes(), &video); err != nil {
			t.Fatal(err)
		}
		if len(video.Subtitles) != 0 {
			t.Fatalf("metadata exposed denied subtitle sidecar: %+v", video.Subtitles)
		}
	})

	t.Run("public album art is safely reencoded", func(t *testing.T) {
		if preview.GetService() == nil {
			if err := preview.StartPreviewGenerator(1, filepath.Join(t.TempDir(), "public-album-art-cache")); err != nil {
				t.Fatal(err)
			}
		}
		rawArt := makeSolidBMP(t, color.RGBA{R: 0x20, G: 0x80, B: 0xE0, A: 0xFF})
		audioPath, _ := writePublicLyricsFixture(t, sourcePath, "album-art", "unused")
		owner := h.newOwner(t, "public-album-art-owner", users.Permissions{
			Share: true, Browse: true, Preview: true, Download: true,
		})
		link := h.saveShare(t, owner, "public-album-art", "/public", nil)
		baseContext := &requestContext{
			user:        &users.User{Username: "anonymous"},
			share:       link,
			shareUser:   owner,
			shareAccess: calculatePublicShareAccess(link, owner),
			shareScope:  "/",
		}
		checked, err := resolvePublicShareTarget(baseContext, sourcePath, "/"+filepath.Base(audioPath))
		if err != nil {
			t.Fatalf("resolve album art target: %v", err)
		}

		originalFileInfoFaster := fsfiles.FileInfoFasterFunc
		fsfiles.FileInfoFasterFunc = func(_ utils.FileOptions, _ *access.Storage, _ *users.User, _ *dbshare.Storage) (*iteminfo.ExtendedFileInfo, error) {
			return &iteminfo.ExtendedFileInfo{
				FileInfo: iteminfo.FileInfo{
					ItemInfo: iteminfo.ItemInfo{Name: filepath.Base(audioPath), Type: "audio/mpeg"},
					Path:     "/public/" + filepath.Base(audioPath),
				},
				Metadata: &iteminfo.MediaMetadata{AlbumArt: append([]byte(nil), rawArt...)},
				RealPath: audioPath,
				Source:   "source1",
			}, nil
		}
		defer func() { fsfiles.FileInfoFasterFunc = originalFileInfoFaster }()

		d := &requestContext{
			user:         baseContext.user,
			share:        link,
			shareUser:    owner,
			shareAccess:  baseContext.shareAccess,
			shareQuery:   url.Values{"albumArt": {"true"}},
			shareScope:   "/",
			shareTargets: []publicShareTarget{checked},
			fileInfo: iteminfo.ExtendedFileInfo{FileInfo: iteminfo.FileInfo{
				ItemInfo: iteminfo.ItemInfo{Name: filepath.Base(audioPath), Type: "audio/mpeg"},
				Path:     "/public/" + filepath.Base(audioPath),
			}, RealPath: audioPath, Source: "source1"},
		}
		recorder := httptest.NewRecorder()
		status, err := publicVerifiedMetadataHandler(recorder, httptest.NewRequest(http.MethodGet, "/public/api/media/metadata?albumArt=true", nil), d)
		if err != nil || status != http.StatusOK {
			t.Fatalf("public album art metadata: status=%d err=%v body=%q", status, err, recorder.Body.String())
		}
		var response iteminfo.ExtendedFileInfo
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Metadata == nil || len(response.Metadata.AlbumArt) == 0 {
			t.Fatal("public album art response is empty")
		}
		if bytes.Equal(response.Metadata.AlbumArt, rawArt) {
			t.Fatal("public album art returned original embedded bytes")
		}
	})
}

func TestMediaMetadataRequiresPreview(t *testing.T) {
	fixture := setupPreviewSecurityFixture(t)
	user := fixture.user(t, true, false, true)
	response := fixture.metadataRequest(t, user, fixture.files["full audio"], false)
	assertPreviewForbidden(t, response)
}

func writePublicLyricsFixture(t *testing.T, sourcePath, stem, lyrics string) (string, string) {
	t.Helper()
	audioPath := filepath.Join(sourcePath, "public", stem+".mp3")
	sidecarPath := filepath.Join(sourcePath, "public", stem+".lrc")
	audio := make([]byte, 128)
	copy(audio, []byte("TAG"))
	if err := os.WriteFile(audioPath, audio, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sidecarPath, []byte("[00:01.00]"+lyrics+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return audioPath, sidecarPath
}

func refreshPublicMediaFixture(t *testing.T) {
	t.Helper()
	idx := indexing.GetIndex("source1")
	if idx == nil {
		t.Fatal("source1 index is unavailable")
	}
	if err := idx.RefreshDirectory("/public", false); err != nil {
		t.Fatalf("refresh public media fixture: %v", err)
	}
}
