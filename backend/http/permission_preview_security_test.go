package http

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/diskcache"
	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/files"
	"github.com/gtsteffaniak/filebrowser/backend/auth"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/access"
	"github.com/gtsteffaniak/filebrowser/backend/database/share"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/indexing/iteminfo"
	"github.com/gtsteffaniak/filebrowser/backend/preview"
	"golang.org/x/image/bmp"
)

const previewOriginalSizeLimit = 256 * 1024

type previewPermissionValue struct {
	name    string
	allowed bool
}

type previewSecurityFile struct {
	indexPath string
	realPath  string
	content   []byte
}

type previewSecurityFixture struct {
	sourcePath   string
	cacheRoot    string
	smallImage   previewSecurityFile
	largeImage   previewSecurityFile
	fittingImage previewSecurityFile
	safeImage    previewSecurityFile
	legacyImage  previewSecurityFile
	files        map[string]previewSecurityFile
	safePreview  []byte
}

type previewSecurityResponse struct {
	status      int
	body        []byte
	contentType string
	err         error
}

func TestPermissionPreviewSecurity(t *testing.T) {
	fixture := setupPreviewSecurityFixture(t)

	t.Run("browse denied blocks a known preview path", func(t *testing.T) {
		user := fixture.user(t, false, true, true)
		response := fixture.previewRequest(t, user, fixture.smallImage, "small", 0)
		assertPreviewForbidden(t, response)
	})

	t.Run("permission denial precedes source lookup", func(t *testing.T) {
		user := fixture.user(t, false, true, true)
		missing := previewSecurityFile{indexPath: "/public/missing-preview.png"}
		response := fixture.previewRequest(t, user, missing, "small", 0)
		assertPreviewForbidden(t, response)
	})

	t.Run("preview denied blocks every derived preview form", func(t *testing.T) {
		user := fixture.user(t, true, false, true)
		tests := []struct {
			name       string
			file       previewSecurityFile
			size       string
			percentage int
		}{
			{name: "thumbnail", file: fixture.smallImage, size: "small"},
			{name: "image preview", file: fixture.largeImage, size: "large"},
			{name: "PDF derived image", file: fixture.files["native PDF"], size: "small"},
			{name: "video frame", file: fixture.files["full video"], size: "small", percentage: 50},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				response := fixture.previewRequest(t, user, test.file, test.size, test.percentage)
				assertPreviewForbidden(t, response)
			})
		}
	})

	t.Run("preview only cannot request the full original image", func(t *testing.T) {
		user := fixture.user(t, true, true, false)
		response := fixture.previewRequest(t, user, fixture.largeImage, "original", 0)
		assertPreviewForbidden(t, response)
	})

	t.Run("small images do not leak through rawFileHandler", func(t *testing.T) {
		if len(fixture.smallImage.content) >= previewOriginalSizeLimit {
			t.Fatalf("small-image fixture is %d bytes; expected less than 256 KiB", len(fixture.smallImage.content))
		}
		user := fixture.user(t, true, true, false)
		response := fixture.previewRequest(t, user, fixture.smallImage, "small", 0)
		assertDerivedPreview(t, response, fixture.smallImage.content, "small")
	})

	t.Run("raw image shortcuts cannot bypass download", func(t *testing.T) {
		user := fixture.user(t, true, true, false)
		tests := []struct {
			name          string
			file          previewSecurityFile
			size          string
			disableResize bool
		}{
			{name: "image already fits requested size", file: fixture.fittingImage, size: "large"},
			{name: "server resize disabled", file: fixture.largeImage, size: "small", disableResize: true},
			{name: "size original", file: fixture.largeImage, size: "original"},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				previousDisableResize := config.Server.DisableResize
				config.Server.DisableResize = test.disableResize
				defer func() { config.Server.DisableResize = previousDisableResize }()

				response := fixture.previewRequest(t, user, test.file, test.size, 0)
				if test.size == "original" {
					assertPreviewForbidden(t, response)
					return
				}
				assertDerivedPreview(t, response, test.file.content, test.size)
			})
		}
	})

	t.Run("download permission preserves original image shortcuts", func(t *testing.T) {
		user := fixture.user(t, true, true, true)
		for _, test := range []struct {
			name          string
			file          previewSecurityFile
			size          string
			disableResize bool
		}{
			{name: "small image", file: fixture.smallImage, size: "small"},
			{name: "image already fits", file: fixture.fittingImage, size: "large"},
			{name: "resize disabled", file: fixture.largeImage, size: "small", disableResize: true},
		} {
			t.Run(test.name, func(t *testing.T) {
				previousDisableResize := config.Server.DisableResize
				config.Server.DisableResize = test.disableResize
				defer func() { config.Server.DisableResize = previousDisableResize }()

				response := fixture.previewRequest(t, user, test.file, test.size, 0)
				if response.status != http.StatusOK || response.err != nil || !bytes.Equal(response.body, test.file.content) {
					t.Errorf("expected permitted original shortcut, got status %d, %d bytes, err %v", response.status, len(response.body), response.err)
				}
			})
		}
	})

	t.Run("preview only responses differ from the source bytes", func(t *testing.T) {
		user := fixture.user(t, true, true, false)
		response := fixture.previewRequest(t, user, fixture.safeImage, "small", 0)
		assertDerivedPreview(t, response, fixture.safeImage.content, "small")
	})

	t.Run("cache hits still require browse and preview", func(t *testing.T) {
		tests := []struct {
			name    string
			field   string
			browse  bool
			preview bool
		}{
			{name: "browse revoked", field: "Browse", browse: false, preview: true},
			{name: "preview revoked", field: "Preview", browse: true, preview: false},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				allowedUser := fixture.user(t, true, true, false)
				fileInfo := fixture.fileInfo(t, allowedUser, fixture.largeImage)
				fixture.seedCurrentCache(t, fileInfo, "small", 0, fixture.safePreview)
				allowedResponse := fixture.previewRequest(t, allowedUser, fixture.largeImage, "small", 0)
				assertDerivedPreview(t, allowedResponse, fixture.largeImage.content, "small")
				if !bytes.Equal(allowedResponse.body, fixture.safePreview) {
					t.Fatal("authorized request did not hit the seeded current cache entry")
				}

				user := fixture.user(t, test.browse, test.preview, false)
				response := fixture.previewRequest(t, user, fixture.largeImage, "small", 0)
				if response.status != http.StatusForbidden {
					t.Errorf("%s before cache read: expected status %d, got %d (err: %v)", test.field, http.StatusForbidden, response.status, response.err)
				}
				if len(response.body) != 0 {
					t.Errorf("%s before cache read: expected an empty body, got %d bytes", test.field, len(response.body))
				}
			})
		}
	})

	t.Run("unsafe entries in the safe cache namespace are regenerated", func(t *testing.T) {
		user := fixture.user(t, true, true, false)
		fileInfo := fixture.fileInfo(t, user, fixture.largeImage)
		for i, test := range []struct {
			name    string
			content []byte
			marker  []byte
		}{
			{name: "original PNG", content: fixture.largeImage.content},
			{name: "short entry", content: []byte("broken")},
			{name: "truncated JPEG", content: fixture.safePreview[:len(fixture.safePreview)-2]},
			{
				name:    "JPEG with trailing payload",
				content: append(append([]byte(nil), fixture.safePreview...), []byte("SAFE-CACHE-TRAILER")...),
				marker:  []byte("SAFE-CACHE-TRAILER"),
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				percentage := 20 + i
				fixture.seedCurrentCache(t, fileInfo, "small", percentage, test.content)

				response := fixture.previewRequest(t, user, fixture.largeImage, "small", percentage)
				assertDerivedPreview(t, response, fixture.largeImage.content, "small")
				if bytes.Equal(response.body, test.content) {
					t.Fatal("request returned the invalid safe-cache entry without regenerating it")
				}
				if len(test.marker) > 0 && bytes.Contains(response.body, test.marker) {
					t.Fatalf("regenerated preview leaked trailing cache payload %q", test.marker)
				}
			})
		}
	})

	t.Run("safe cache detects same size and mtime content replacement", func(t *testing.T) {
		contentA := makeSolidBMP(t, color.RGBA{R: 0xf0, G: 0x20, B: 0x20, A: 0xff})
		contentB := makeSolidBMP(t, color.RGBA{R: 0x20, G: 0x20, B: 0xf0, A: 0xff})
		if len(contentA) != len(contentB) || bytes.Equal(contentA, contentB) {
			t.Fatalf("replacement fixtures must have equal lengths and different content: A=%d B=%d", len(contentA), len(contentB))
		}

		file := fixture.writeFile(t, "same-version.bmp", contentA)
		originalStat, err := os.Stat(file.realPath)
		if err != nil {
			t.Fatal(err)
		}
		user := fixture.user(t, true, true, false)
		fileInfoA := fixture.fileInfo(t, user, file)
		keyA, err := preview.SafeCacheKey(fileInfoA, "small", 0)
		if err != nil {
			t.Fatal(err)
		}

		first := fixture.previewRequest(t, user, file, "small", 0)
		assertDerivedPreview(t, first, contentA, "small")
		assertDominantPreviewColor(t, first.body, true)
		cache, err := diskcache.NewFileCache(fixture.cacheRoot)
		if err != nil {
			t.Fatal(err)
		}
		cachedA, found, err := cache.Load(context.Background(), keyA)
		if err != nil {
			t.Fatal(err)
		}
		if !found || !bytes.Equal(cachedA, first.body) {
			t.Fatal("first preview did not populate the expected safe cache entry")
		}

		if err := os.WriteFile(file.realPath, contentB, 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(file.realPath, originalStat.ModTime(), originalStat.ModTime()); err != nil {
			t.Fatal(err)
		}
		replacementStat, err := os.Stat(file.realPath)
		if err != nil {
			t.Fatal(err)
		}
		if replacementStat.Size() != originalStat.Size() || !replacementStat.ModTime().Equal(originalStat.ModTime()) {
			t.Fatalf("replacement metadata differs: before size=%d mtime=%s, after size=%d mtime=%s",
				originalStat.Size(), originalStat.ModTime(), replacementStat.Size(), replacementStat.ModTime())
		}

		replacement := file
		replacement.content = contentB
		second := fixture.previewRequest(t, user, replacement, "small", 0)
		assertDerivedPreview(t, second, contentB, "small")
		if bytes.Equal(second.body, first.body) {
			t.Fatal("same-size same-mtime replacement returned the previous file's safe cache entry")
		}
		assertDominantPreviewColor(t, second.body, false)

		fileInfoB := fixture.fileInfo(t, user, replacement)
		keyB, err := preview.SafeCacheKey(fileInfoB, "small", 0)
		if err != nil {
			t.Fatal(err)
		}
		if keyA == keyB {
			t.Fatal("safe cache key did not change after same-size same-mtime content replacement")
		}
	})

	t.Run("legacy cache entries containing originals are not preview only content", func(t *testing.T) {
		user := fixture.user(t, true, true, false)
		fileInfo := fixture.fileInfo(t, user, fixture.legacyImage)
		fixture.seedLegacyCache(t, fileInfo, "small", 0, fixture.legacyImage.content)

		response := fixture.previewRequest(t, user, fixture.legacyImage, "small", 0)
		assertDerivedPreview(t, response, fixture.legacyImage.content, "small")
	})

	t.Run("public share preview retains the legacy cache path", func(t *testing.T) {
		user := fixture.user(t, true, true, false)
		fileInfo := fixture.fileInfo(t, user, fixture.largeImage)
		fixture.seedLegacyCache(t, fileInfo, "small", 0, fixture.safePreview)

		query := url.Values{"size": {"small"}}
		req := httptest.NewRequest(http.MethodGet, "/public/api/resources/preview?"+query.Encode(), nil)
		recorder := httptest.NewRecorder()
		status, err := previewHelperFunc(recorder, req, &requestContext{
			user:     user,
			share:    &share.Link{},
			fileInfo: fileInfo,
		})
		response := responseFromRecorder(recorder, status, err)
		assertDerivedPreview(t, response, fixture.largeImage.content, "small")
		if !bytes.Equal(response.body, fixture.safePreview) {
			t.Fatal("public share preview did not use the seeded legacy cache entry")
		}
	})

	t.Run("album art metadata requires browse and preview before source access", func(t *testing.T) {
		for _, test := range []struct {
			name    string
			browse  bool
			preview bool
		}{
			{name: "browse denied", browse: false, preview: true},
			{name: "preview denied", browse: true, preview: false},
		} {
			t.Run(test.name, func(t *testing.T) {
				user := fixture.user(t, test.browse, test.preview, false)
				response := fixture.metadataRequest(t, user, fixture.files["full audio"], true)
				assertPreviewForbidden(t, response)
			})
		}
	})

	t.Run("media metadata without album art still requires browse", func(t *testing.T) {
		user := fixture.user(t, false, true, true)
		response := fixture.metadataRequest(t, user, fixture.files["full audio"], false)
		assertPreviewForbidden(t, response)
	})

	t.Run("album art metadata reencodes directory child covers", func(t *testing.T) {
		originalCover := fixture.fittingImage.content
		originalFileInfoFaster := files.FileInfoFasterFunc
		files.FileInfoFasterFunc = func(_ utils.FileOptions, _ *access.Storage, _ *users.User, _ *share.Storage) (*iteminfo.ExtendedFileInfo, error) {
			return &iteminfo.ExtendedFileInfo{
				FileInfo: iteminfo.FileInfo{
					ItemInfo: iteminfo.ItemInfo{Name: "music", Type: "directory"},
					Path:     "/public/music",
					Files: []iteminfo.ExtendedItemInfo{
						{
							ItemInfo: iteminfo.ItemInfo{
								Name:       "track.mp3",
								Size:       int64(len(originalCover)),
								ModTime:    time.Now(),
								Type:       "audio/mpeg",
								HasPreview: true,
							},
							Metadata: &iteminfo.MediaMetadata{AlbumArt: append([]byte(nil), originalCover...)},
						},
					},
				},
				Source:   "source1",
				RealPath: filepath.Join(fixture.sourcePath, "public", "music"),
			}, nil
		}
		defer func() { files.FileInfoFasterFunc = originalFileInfoFaster }()

		user := fixture.user(t, true, true, false)
		response := fixture.metadataRequest(t, user, fixture.files["full audio"], true)
		if response.status != http.StatusOK || response.err != nil {
			t.Fatalf("directory album art request: status %d, err %v", response.status, response.err)
		}
		var decoded iteminfo.ExtendedFileInfo
		if err := json.Unmarshal(response.body, &decoded); err != nil {
			t.Fatalf("decode directory album art response: %v", err)
		}
		if len(decoded.Files) != 1 || decoded.Files[0].Metadata == nil {
			t.Fatalf("directory album art response did not include the expected child metadata: %+v", decoded.Files)
		}
		assertDerivedImageBytes(t, decoded.Files[0].Metadata.AlbumArt, originalCover, "small")
	})

	t.Run("full media viewer helpers require browse and download", func(t *testing.T) {
		for _, test := range []struct {
			name     string
			browse   bool
			download bool
		}{
			{name: "browse denied", browse: false, download: true},
			{name: "download denied", browse: true, download: false},
		} {
			t.Run(test.name, func(t *testing.T) {
				user := fixture.user(t, test.browse, true, test.download)
				assertPreviewForbidden(t, fixture.subtitlesRequest(t, user, fixture.files["full video"]))
				assertPreviewForbidden(t, fixture.lyricsRequest(t, user, fixture.files["full audio"]))
			})
		}
	})

	t.Run("media sidecars require their own access rule", func(t *testing.T) {
		for _, test := range []struct {
			name     string
			sidecar  previewSecurityFile
			request  func(*testing.T, *users.User) previewSecurityResponse
			sentinel []byte
			username string
		}{
			{
				name:    "subtitle",
				sidecar: fixture.files["subtitle sidecar"],
				request: func(t *testing.T, user *users.User) previewSecurityResponse {
					return fixture.subtitlesRequest(t, user, fixture.files["full video"])
				},
				sentinel: []byte("PREVIEW-SUBTITLE-SIDECAR"),
				username: "preview-subtitle-sidecar-user",
			},
			{
				name:    "lyrics",
				sidecar: fixture.files["lyrics sidecar"],
				request: func(t *testing.T, user *users.User) previewSecurityResponse {
					return fixture.lyricsRequest(t, user, fixture.files["lyrics audio"])
				},
				sentinel: []byte("PREVIEW-LYRICS-SIDECAR"),
				username: "preview-lyrics-sidecar-user",
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				user := fixture.user(t, true, true, true)
				user.Username = test.username
				if err := store.Users.Save(user, false, false); err != nil {
					t.Fatal(err)
				}

				allowed := test.request(t, user)
				if allowed.status != http.StatusOK || allowed.err != nil || !bytes.Contains(allowed.body, test.sentinel) {
					t.Fatalf("allowed %s sidecar request: status %d, body %q, err %v", test.name, allowed.status, allowed.body, allowed.err)
				}

				if err := store.Access.DenyUser(fixture.sourcePath, test.sidecar.indexPath, user.Username); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := store.Access.RemoveDenyUser(fixture.sourcePath, test.sidecar.indexPath, user.Username); err != nil {
						t.Errorf("remove %s sidecar deny rule: %v", test.name, err)
					}
				}()

				denied := test.request(t, user)
				assertSidecarDenied(t, denied, test.sentinel)
			})
		}
	})

	t.Run("subtitle sidecar path traversal is rejected", func(t *testing.T) {
		response := fixture.subtitlesNamedRequest(t, fixture.user(t, true, true, true), fixture.files["full video"], "../video.srt")
		assertSidecarDenied(t, response, fixture.files["subtitle sidecar"].content)
	})

	t.Run("media sidecar symlinks are rejected", func(t *testing.T) {
		for _, test := range []struct {
			name     string
			sidecar  previewSecurityFile
			request  func(*testing.T, *users.User) previewSecurityResponse
			sentinel []byte
		}{
			{
				name:    "subtitle",
				sidecar: fixture.files["subtitle sidecar"],
				request: func(t *testing.T, user *users.User) previewSecurityResponse {
					return fixture.subtitlesRequest(t, user, fixture.files["full video"])
				},
				sentinel: []byte("OUTSIDE-SUBTITLE-SENTINEL"),
			},
			{
				name:    "lyrics",
				sidecar: fixture.files["lyrics sidecar"],
				request: func(t *testing.T, user *users.User) previewSecurityResponse {
					return fixture.lyricsRequest(t, user, fixture.files["lyrics audio"])
				},
				sentinel: []byte("OUTSIDE-LYRICS-SENTINEL"),
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				outsidePath := filepath.Join(t.TempDir(), test.name+"-outside.txt")
				if err := os.WriteFile(outsidePath, test.sentinel, 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(test.sidecar.realPath); err != nil {
					t.Fatal(err)
				}
				defer func() {
					_ = os.Remove(test.sidecar.realPath)
					if err := os.WriteFile(test.sidecar.realPath, test.sidecar.content, 0644); err != nil {
						t.Errorf("restore %s sidecar: %v", test.name, err)
					}
				}()
				if err := os.Symlink(outsidePath, test.sidecar.realPath); err != nil {
					t.Skipf("cannot create sidecar symlink in this environment: %v", err)
				}

				response := test.request(t, fixture.user(t, true, true, true))
				assertSidecarDenied(t, response, test.sentinel)
			})
		}
	})

	t.Run("original content viewers require download", func(t *testing.T) {
		user := fixture.user(t, true, true, false)
		for _, name := range []string{"native PDF", "full video", "full audio", "Office", "EPUB", "3D model"} {
			t.Run(name, func(t *testing.T) {
				response := fixture.downloadRequest(t, user, fixture.files[name])
				assertPreviewForbidden(t, response)
			})
		}

		t.Run("OnlyOffice", func(t *testing.T) {
			previousOnlyOffice := config.Integrations.OnlyOffice
			config.Integrations.OnlyOffice.Url = "http://onlyoffice.test"
			config.Integrations.OnlyOffice.Secret = ""
			defer func() { config.Integrations.OnlyOffice = previousOnlyOffice }()

			officeFile := fixture.files["Office"]
			utils.OnlyOfficeCache.Set(officeFile.realPath, "preview-security-document-key")
			defer utils.OnlyOfficeCache.Delete(officeFile.realPath)

			for _, test := range []struct {
				name      string
				browse    bool
				preview   bool
				download  bool
				forbidden bool
			}{
				{name: "download denied", browse: true, preview: true, download: false, forbidden: true},
				{name: "browse denied", browse: false, preview: true, download: true, forbidden: true},
				{name: "preview is not required", browse: true, preview: false, download: true},
			} {
				t.Run(test.name, func(t *testing.T) {
					query := url.Values{
						"source": {"source1"},
						"path":   {officeFile.indexPath},
					}
					req := httptest.NewRequest(http.MethodGet, "/api/office/config?"+query.Encode(), nil)
					recorder := httptest.NewRecorder()
					requestUser := fixture.user(t, test.browse, test.preview, test.download)
					status, err := onlyofficeClientConfigGetHandler(recorder, req, &requestContext{user: requestUser, token: "preview-security-token"})
					response := responseFromRecorder(recorder, status, err)
					if test.forbidden {
						assertPreviewForbidden(t, response)
						return
					}
					if response.status != http.StatusOK || response.err != nil || len(response.body) == 0 {
						t.Errorf("expected OnlyOffice config for Browse+Download, got status %d, %d bytes, err %v", response.status, len(response.body), response.err)
					}
				})
			}

			t.Run("public share is not subject to user permission gate", func(t *testing.T) {
				publicFileInfo := fixture.fileInfo(t, fixture.user(t, true, true, true), officeFile)
				publicFileInfo.Hash = "preview-security-public-share"
				publicLink := &share.Link{
					CommonShare: share.CommonShare{
						Source: fixture.sourcePath,
						Path:   "/public/",
					},
					Hash: publicFileInfo.Hash,
				}
				query := url.Values{
					"hash": {publicLink.Hash},
					"path": {officeFile.indexPath},
				}
				req := httptest.NewRequest(http.MethodGet, "/public/api/office/config?"+query.Encode(), nil)
				recorder := httptest.NewRecorder()
				status, err := onlyofficeClientConfigGetHandler(recorder, req, &requestContext{
					user:     fixture.user(t, false, false, false),
					share:    publicLink,
					fileInfo: publicFileInfo,
					token:    "preview-security-share-token",
				})
				response := responseFromRecorder(recorder, status, err)
				if response.status != http.StatusOK || response.err != nil || len(response.body) == 0 {
					t.Errorf("expected public OnlyOffice config to bypass user permission gate, got status %d, %d bytes, err %v", response.status, len(response.body), response.err)
				}
			})

			t.Run("regular request cannot select the public hash branch", func(t *testing.T) {
				query := url.Values{
					"source": {"source1"},
					"path":   {officeFile.indexPath},
					"hash":   {"untrusted-regular-hash"},
				}
				req := httptest.NewRequest(http.MethodGet, "/api/office/config?"+query.Encode(), nil)
				recorder := httptest.NewRecorder()
				status, err := onlyofficeClientConfigGetHandler(recorder, req, &requestContext{
					user:  fixture.user(t, true, false, true),
					token: "preview-security-token",
				})
				response := responseFromRecorder(recorder, status, err)
				if response.status != http.StatusBadRequest || response.err == nil || len(response.body) != 0 {
					t.Errorf("expected regular hash request to fail safely with 400, got status %d, %d bytes, err %v", response.status, len(response.body), response.err)
				}
			})
		})
	})

	t.Run("preview revocation applies to the next cached request", func(t *testing.T) {
		for i, test := range []struct {
			name  string
			field string
		}{
			{name: "browse revoked", field: "Browse"},
			{name: "preview revoked", field: "Preview"},
		} {
			t.Run(test.name, func(t *testing.T) {
				permissions := previewSecurityPermissions(t, true, true, false)
				user := &users.User{
					Username:    fmt.Sprintf("preview-revocation-user-%d", i),
					Permissions: permissions,
					Scopes: []users.SourceScope{
						{Name: fixture.sourcePath, Scope: "/"},
					},
				}
				if err := store.Users.Save(user, false, false); err != nil {
					t.Fatal(err)
				}

				tokenName := fmt.Sprintf("WEB_TOKEN_preview_revocation_%d", i)
				token, _, err := auth.MakeSignedTokenAPI(user, tokenName, time.Hour, permissions, false)
				if err != nil {
					t.Fatal(err)
				}
				fileInfo := fixture.fileInfo(t, user, fixture.safeImage)
				fixture.seedCurrentCache(t, fileInfo, "small", 0, fixture.safePreview)

				first := fixture.authenticatedPreviewRequest(t, token, fixture.safeImage, "small")
				assertDerivedPreview(t, first, fixture.safeImage.content, "small")
				if !bytes.Equal(first.body, fixture.safePreview) {
					t.Fatal("authorized request did not hit the seeded cache before revocation")
				}

				revokedPermissions := user.Permissions
				setPreviewPermissionFields(t, &revokedPermissions, previewPermissionValue{name: test.field, allowed: false})
				user.Permissions = revokedPermissions
				if err := store.Users.Update(user, true, "Permissions"); err != nil {
					t.Fatal(err)
				}

				second := fixture.authenticatedPreviewRequest(t, token, fixture.safeImage, "small")
				assertPreviewForbidden(t, second)
			})
		}
	})

	t.Run("API token permissions intersect browse preview and download", func(t *testing.T) {
		tests := []struct {
			name            string
			accountBrowse   bool
			accountPreview  bool
			accountDownload bool
			tokenBrowse     bool
			tokenPreview    bool
			tokenDownload   bool
			size            string
			forbidden       bool
			expectOriginal  bool
		}{
			{name: "derived preview allowed without download", accountBrowse: true, accountPreview: true, tokenBrowse: true, tokenPreview: true},
			{name: "token revokes browse", accountBrowse: true, accountPreview: true, tokenBrowse: false, tokenPreview: true, forbidden: true},
			{name: "token revokes preview", accountBrowse: true, accountPreview: true, tokenBrowse: true, tokenPreview: false, forbidden: true},
			{name: "account revokes browse", accountBrowse: false, accountPreview: true, tokenBrowse: true, tokenPreview: true, forbidden: true},
			{name: "account revokes preview", accountBrowse: true, accountPreview: false, tokenBrowse: true, tokenPreview: true, forbidden: true},
			{name: "token revokes download for original", accountBrowse: true, accountPreview: true, accountDownload: true, tokenBrowse: true, tokenPreview: true, size: "original", forbidden: true},
			{name: "account revokes download for original", accountBrowse: true, accountPreview: true, tokenBrowse: true, tokenPreview: true, tokenDownload: true, size: "original", forbidden: true},
			{name: "original allowed by permission intersection", accountBrowse: true, accountPreview: true, accountDownload: true, tokenBrowse: true, tokenPreview: true, tokenDownload: true, size: "original", expectOriginal: true},
		}

		for i, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				accountPermissions := previewSecurityPermissions(t, test.accountBrowse, test.accountPreview, test.accountDownload)
				user := &users.User{
					Username:    fmt.Sprintf("preview-token-user-%d", i),
					Permissions: accountPermissions,
					Scopes: []users.SourceScope{
						{Name: fixture.sourcePath, Scope: "/"},
					},
				}
				if err := store.Users.Save(user, false, false); err != nil {
					t.Fatal(err)
				}

				tokenPermissions := previewSecurityPermissions(t, test.tokenBrowse, test.tokenPreview, test.tokenDownload)
				tokenName := fmt.Sprintf("preview-security-token-%d", i)
				token, metadata, err := auth.MakeSignedTokenAPI(user, tokenName, time.Hour, tokenPermissions, false)
				if err != nil {
					t.Fatal(err)
				}
				if err := store.Users.AddApiToken(user.ID, tokenName, token, metadata); err != nil {
					t.Fatal(err)
				}
				if err := store.Access.AddApiToken(token, user.ID); err != nil {
					t.Fatal(err)
				}

				requestSize := test.size
				if requestSize == "" {
					requestSize = "small"
				}
				if requestSize != "original" {
					fileInfo := fixture.fileInfo(t, user, fixture.safeImage)
					fixture.seedCurrentCache(t, fileInfo, requestSize, 0, fixture.safePreview)
				}
				response := fixture.authenticatedPreviewRequest(t, token, fixture.safeImage, requestSize)
				if test.forbidden {
					assertPreviewForbidden(t, response)
					return
				}
				if test.expectOriginal {
					if response.status != http.StatusOK || response.err != nil || !bytes.Equal(response.body, fixture.safeImage.content) {
						t.Errorf("expected permitted original image, got status %d, %d bytes, err %v", response.status, len(response.body), response.err)
					}
					return
				}
				assertDerivedPreview(t, response, fixture.safeImage.content, requestSize)
			})
		}
	})
}

func setupPreviewSecurityFixture(t *testing.T) *previewSecurityFixture {
	t.Helper()

	sourcePath := setupResourcePutTestEnv(t)
	previousAuthKey := settings.Config.Auth.Key
	settings.Config.Auth.Key = "preview-security-test-key"
	config.Auth.Key = settings.Config.Auth.Key
	t.Cleanup(func() { settings.Config.Auth.Key = previousAuthKey })

	cacheRoot := filepath.Join(filepath.Dir(sourcePath), "preview-security-cache")
	if err := preview.StartPreviewGenerator(1, cacheRoot); err != nil {
		t.Fatal(err)
	}

	fixture := &previewSecurityFixture{
		sourcePath: sourcePath,
		cacheRoot:  cacheRoot,
		files:      make(map[string]previewSecurityFile),
	}
	fixture.smallImage = fixture.writeImage(t, "small.png", 48, 48, 1)
	fixture.largeImage = fixture.writeImage(t, "large.png", 768, 768, 2)
	fixture.fittingImage = fixture.writeImage(t, "fitting.png", 512, 512, 3)
	fixture.safeImage = fixture.writeImage(t, "safe.png", 769, 769, 4)
	fixture.legacyImage = fixture.writeImage(t, "legacy.png", 770, 770, 5)
	fixture.files["native PDF"] = fixture.writeFile(t, "document.pdf", []byte("%PDF-1.7\npreview security fixture\n%%EOF\n"))
	fixture.files["full video"] = fixture.writeFile(t, "video.mp4", []byte("preview-security-video-original"))
	fixture.files["full audio"] = fixture.writeFile(t, "audio.mp3", []byte("preview-security-audio-original"))
	fixture.files["subtitle sidecar"] = fixture.writeFile(t, "video.srt", []byte("1\n00:00:01,000 --> 00:00:02,000\nPREVIEW-SUBTITLE-SIDECAR\n"))
	lyricsAudio := make([]byte, 128)
	copy(lyricsAudio, []byte("TAG"))
	fixture.files["lyrics audio"] = fixture.writeFile(t, "lyrics.mp3", lyricsAudio)
	fixture.files["lyrics sidecar"] = fixture.writeFile(t, "lyrics.lrc", []byte("[00:01.00]PREVIEW-LYRICS-SIDECAR\n"))
	fixture.files["Office"] = fixture.writeFile(t, "document.docx", []byte("preview-security-office-original"))
	fixture.files["EPUB"] = fixture.writeFile(t, "book.epub", []byte("preview-security-epub-original"))
	fixture.files["3D model"] = fixture.writeFile(t, "model.glb", []byte("preview-security-model-original"))
	fixture.safePreview = makePreviewJPEG(t)

	for name, file := range map[string]previewSecurityFile{
		"large":   fixture.largeImage,
		"fitting": fixture.fittingImage,
		"safe":    fixture.safeImage,
		"legacy":  fixture.legacyImage,
	} {
		if len(file.content) <= previewOriginalSizeLimit {
			t.Fatalf("%s image fixture is %d bytes; expected more than 256 KiB", name, len(file.content))
		}
	}

	return fixture
}

func (fixture *previewSecurityFixture) user(t *testing.T, browse, previewAllowed, download bool) *users.User {
	t.Helper()
	return &users.User{
		Username:    "preview-security-user",
		Permissions: previewSecurityPermissions(t, browse, previewAllowed, download),
		Scopes: []users.SourceScope{
			{Name: fixture.sourcePath, Scope: "/"},
		},
	}
}

func previewSecurityPermissions(t *testing.T, browse, previewAllowed, download bool) users.Permissions {
	t.Helper()
	permissions := users.Permissions{Api: true, Download: download}
	setPreviewPermissionFields(t, &permissions,
		previewPermissionValue{name: "Browse", allowed: browse},
		previewPermissionValue{name: "Preview", allowed: previewAllowed},
	)
	return permissions
}

func setPreviewPermissionFields(t *testing.T, permissions *users.Permissions, values ...previewPermissionValue) {
	t.Helper()
	if permissions == nil {
		t.Fatal("preview permission fixture received nil *users.Permissions")
	}

	target := reflect.ValueOf(permissions).Elem()
	fields := make([]reflect.Value, len(values))
	invalid := false
	for i, value := range values {
		field := target.FieldByName(value.name)
		switch {
		case !field.IsValid():
			t.Errorf("preview security contract requires users.Permissions.%s, but that field is missing", value.name)
			invalid = true
		case field.Kind() != reflect.Bool:
			t.Errorf("users.Permissions.%s must be bool, got %s", value.name, field.Kind())
			invalid = true
		case !field.CanSet():
			t.Errorf("users.Permissions.%s is not settable in the preview security fixture", value.name)
			invalid = true
		default:
			fields[i] = field
		}
	}
	if invalid {
		t.FailNow()
	}
	for i, value := range values {
		fields[i].SetBool(value.allowed)
	}
}

func (fixture *previewSecurityFixture) writeImage(t *testing.T, name string, width, height int, seed uint32) previewSecurityFile {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, width, height))
	state := seed
	for i := 0; i < len(img.Pix); i += 4 {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		img.Pix[i] = byte(state)
		img.Pix[i+1] = byte(state >> 8)
		img.Pix[i+2] = byte(state >> 16)
		img.Pix[i+3] = 0xff
	}

	var encoded bytes.Buffer
	if err := png.Encode(&encoded, img); err != nil {
		t.Fatal(err)
	}
	return fixture.writeFile(t, name, encoded.Bytes())
}

func makePreviewJPEG(t *testing.T) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, 64, 64))
	for y := 0; y < 64; y++ {
		for x := 0; x < 64; x++ {
			offset := img.PixOffset(x, y)
			img.Pix[offset] = byte(x * 4)
			img.Pix[offset+1] = byte(y * 4)
			img.Pix[offset+2] = byte((x + y) * 2)
			img.Pix[offset+3] = 0xff
		}
	}

	var encoded bytes.Buffer
	if err := jpeg.Encode(&encoded, img, &jpeg.Options{Quality: 70}); err != nil {
		t.Fatal(err)
	}
	if encoded.Len() < 100 {
		t.Fatalf("safe preview fixture is unexpectedly small: %d bytes", encoded.Len())
	}
	return encoded.Bytes()
}

func makeSolidBMP(t *testing.T, fill color.Color) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 320, 180))
	for y := 0; y < img.Bounds().Dy(); y++ {
		for x := 0; x < img.Bounds().Dx(); x++ {
			img.Set(x, y, fill)
		}
	}
	var encoded bytes.Buffer
	if err := bmp.Encode(&encoded, img); err != nil {
		t.Fatal(err)
	}
	return encoded.Bytes()
}

func (fixture *previewSecurityFixture) writeFile(t *testing.T, name string, content []byte) previewSecurityFile {
	t.Helper()
	indexPath := "/public/" + name
	realPath := filepath.Join(fixture.sourcePath, "public", name)
	if err := os.WriteFile(realPath, content, 0644); err != nil {
		t.Fatal(err)
	}
	return previewSecurityFile{
		indexPath: indexPath,
		realPath:  realPath,
		content:   append([]byte(nil), content...),
	}
}

func (fixture *previewSecurityFixture) fileInfo(t *testing.T, user *users.User, file previewSecurityFile) iteminfo.ExtendedFileInfo {
	t.Helper()
	info, err := files.FileInfoFaster(utils.FileOptions{
		Path:     file.indexPath,
		Source:   "source1",
		AlbumArt: true,
		Expand:   true,
	}, store.Access, user, store.Share)
	if err != nil {
		t.Fatalf("load preview fixture %s: %v", file.indexPath, err)
	}
	return *info
}

func (fixture *previewSecurityFixture) previewRequest(t *testing.T, user *users.User, file previewSecurityFile, size string, percentage int) previewSecurityResponse {
	t.Helper()
	query := url.Values{
		"source": {"source1"},
		"path":   {file.indexPath},
		"size":   {size},
	}
	if percentage != 0 {
		query.Set("atPercentage", fmt.Sprintf("%d", percentage))
	}
	req := httptest.NewRequest(http.MethodGet, "/api/resources/preview?"+query.Encode(), nil)
	recorder := httptest.NewRecorder()
	status, err := previewHandler(recorder, req, &requestContext{user: user})
	return responseFromRecorder(recorder, status, err)
}

func (fixture *previewSecurityFixture) authenticatedPreviewRequest(t *testing.T, token string, file previewSecurityFile, size string) previewSecurityResponse {
	t.Helper()
	query := url.Values{
		"source": {"source1"},
		"path":   {file.indexPath},
		"size":   {size},
	}
	req := httptest.NewRequest(http.MethodGet, "/api/resources/preview?"+query.Encode(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	status, err := withUserHelper(previewHandler)(recorder, req, &requestContext{})
	return responseFromRecorder(recorder, status, err)
}

func (fixture *previewSecurityFixture) downloadRequest(t *testing.T, user *users.User, file previewSecurityFile) previewSecurityResponse {
	t.Helper()
	query := url.Values{
		"source": {"source1"},
		"file":   {file.indexPath},
		"inline": {"true"},
	}
	req := httptest.NewRequest(http.MethodGet, "/api/resources/download?"+query.Encode(), nil)
	recorder := httptest.NewRecorder()
	status, err := downloadHandler(recorder, req, &requestContext{user: user})
	return responseFromRecorder(recorder, status, err)
}

func (fixture *previewSecurityFixture) metadataRequest(t *testing.T, user *users.User, file previewSecurityFile, albumArt bool) previewSecurityResponse {
	t.Helper()
	query := url.Values{
		"source": {"source1"},
		"path":   {file.indexPath},
	}
	if albumArt {
		query.Set("albumArt", "true")
	}
	req := httptest.NewRequest(http.MethodGet, "/api/media/metadata?"+query.Encode(), nil)
	recorder := httptest.NewRecorder()
	status, err := metadataHandler(recorder, req, &requestContext{user: user})
	return responseFromRecorder(recorder, status, err)
}

func (fixture *previewSecurityFixture) subtitlesRequest(t *testing.T, user *users.User, file previewSecurityFile) previewSecurityResponse {
	t.Helper()
	return fixture.subtitlesNamedRequest(t, user, file, "video.srt")
}

func (fixture *previewSecurityFixture) subtitlesNamedRequest(t *testing.T, user *users.User, file previewSecurityFile, name string) previewSecurityResponse {
	t.Helper()
	query := url.Values{
		"source":   {"source1"},
		"path":     {file.indexPath},
		"name":     {name},
		"embedded": {"false"},
	}
	req := httptest.NewRequest(http.MethodGet, "/api/media/subtitles?"+query.Encode(), nil)
	recorder := httptest.NewRecorder()
	status, err := subtitlesHandler(recorder, req, &requestContext{user: user})
	return responseFromRecorder(recorder, status, err)
}

func (fixture *previewSecurityFixture) lyricsRequest(t *testing.T, user *users.User, file previewSecurityFile) previewSecurityResponse {
	t.Helper()
	query := url.Values{
		"source": {"source1"},
		"path":   {file.indexPath},
	}
	req := httptest.NewRequest(http.MethodGet, "/api/media/lyrics?"+query.Encode(), nil)
	recorder := httptest.NewRecorder()
	status, err := lyricsHandler(recorder, req, &requestContext{user: user})
	return responseFromRecorder(recorder, status, err)
}

func responseFromRecorder(recorder *httptest.ResponseRecorder, status int, err error) previewSecurityResponse {
	if status == 0 {
		status = recorder.Result().StatusCode
	}
	return previewSecurityResponse{
		status:      status,
		body:        append([]byte(nil), recorder.Body.Bytes()...),
		contentType: recorder.Header().Get("Content-Type"),
		err:         err,
	}
}

func (fixture *previewSecurityFixture) seedCurrentCache(t *testing.T, file iteminfo.ExtendedFileInfo, size string, percentage int, content []byte) {
	t.Helper()
	key, err := preview.SafeCacheKey(file, size, percentage)
	if err != nil {
		t.Fatal(err)
	}
	cacheHash := previewSecurityMetadataHash(file)
	legacyKey := fmt.Sprintf("%x%x%x", cacheHash, size, percentage)
	if key == legacyKey {
		t.Fatalf("current preview cache key %q still matches the legacy namespace", key)
	}
	fixture.storeCacheEntry(t, key, content)
}

func (fixture *previewSecurityFixture) seedLegacyCache(t *testing.T, file iteminfo.ExtendedFileInfo, size string, percentage int, content []byte) {
	t.Helper()
	cacheHash := previewSecurityMetadataHash(file)
	// Keep the pre-permission cache key literal so future key versioning still exercises old entries.
	legacyKey := fmt.Sprintf("%x%x%x", cacheHash, size, percentage)
	fixture.storeCacheEntry(t, legacyKey, content)
}

func (fixture *previewSecurityFixture) storeCacheEntry(t *testing.T, key string, content []byte) {
	t.Helper()
	cache, err := diskcache.NewFileCache(fixture.cacheRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Store(context.Background(), key, content); err != nil {
		t.Fatal(err)
	}
	stored, found, err := cache.Load(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatalf("preview cache fixture %q was not stored", key)
	}
	if !bytes.Equal(stored, content) {
		t.Fatalf("preview cache fixture %q changed while being stored", key)
	}
}

func previewSecurityMetadataHash(file iteminfo.ExtendedFileInfo) string {
	hasher := md5.New()
	cacheString := fmt.Sprintf("%s:%d:%s", file.RealPath, file.Size, file.ModTime.Format(time.RFC3339Nano))
	_, _ = hasher.Write([]byte(cacheString))
	return hex.EncodeToString(hasher.Sum(nil))
}

func assertPreviewForbidden(t *testing.T, response previewSecurityResponse) {
	t.Helper()
	if response.status != http.StatusForbidden {
		t.Errorf("expected status %d, got %d (content-type: %q, err: %v)", http.StatusForbidden, response.status, response.contentType, response.err)
	}
	if len(response.body) != 0 {
		t.Errorf("expected forbidden response to contain no file bytes, got %d bytes", len(response.body))
	}
}

func assertSidecarDenied(t *testing.T, response previewSecurityResponse, sentinel []byte) {
	t.Helper()
	if response.status != http.StatusForbidden && response.status != http.StatusNotFound {
		t.Errorf("expected sidecar denial status 403 or 404, got %d (content-type: %q, err: %v)", response.status, response.contentType, response.err)
	}
	if len(response.body) != 0 {
		t.Errorf("expected sidecar denial to contain no bytes, got %d", len(response.body))
	}
	if bytes.Contains(response.body, sentinel) {
		t.Errorf("sidecar denial leaked sentinel %q", sentinel)
	}
}

func assertDominantPreviewColor(t *testing.T, content []byte, red bool) {
	t.Helper()
	decoded, _, err := image.Decode(bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	bounds := decoded.Bounds()
	r, _, b, _ := decoded.At(bounds.Min.X+bounds.Dx()/2, bounds.Min.Y+bounds.Dy()/2).RGBA()
	if red && r <= b {
		t.Fatalf("preview center is not red-dominant: red=%d blue=%d", r, b)
	}
	if !red && b <= r {
		t.Fatalf("preview center is not blue-dominant: red=%d blue=%d", r, b)
	}
}

func assertDerivedPreview(t *testing.T, response previewSecurityResponse, original []byte, size string) {
	t.Helper()
	if response.status != http.StatusOK {
		t.Fatalf("expected derived preview status %d, got %d (err: %v)", http.StatusOK, response.status, response.err)
	}
	if response.err != nil {
		t.Errorf("derived preview returned an error: %v", response.err)
	}
	if response.contentType != "image/jpeg" {
		t.Errorf("derived preview content type = %q; expected image/jpeg", response.contentType)
	}
	assertDerivedImageBytes(t, response.body, original, size)
}

func assertDerivedImageBytes(t *testing.T, derived, original []byte, size string) {
	t.Helper()
	if len(derived) == 0 {
		t.Fatal("derived preview returned an empty body")
	}
	if bytes.Equal(derived, original) {
		t.Errorf("preview-only response exposed all %d original bytes", len(original))
	}
	decoded, format, err := image.Decode(bytes.NewReader(derived))
	if err != nil {
		t.Fatalf("derived preview is not a decodable image: %v", err)
	}
	if format != "jpeg" {
		t.Errorf("derived preview format = %q; expected jpeg", format)
	}
	maxDimension, ok := map[string]int{
		"small":  256,
		"large":  640,
		"xlarge": 1024,
	}[size]
	if !ok {
		t.Fatalf("no derived preview dimension limit defined for size %q", size)
	}
	bounds := decoded.Bounds()
	if bounds.Dx() <= 0 || bounds.Dy() <= 0 || bounds.Dx() > maxDimension || bounds.Dy() > maxDimension {
		t.Errorf("derived %s preview dimensions = %dx%d; expected positive dimensions no larger than %dx%d",
			size, bounds.Dx(), bounds.Dy(), maxDimension, maxDimension)
	}
}
