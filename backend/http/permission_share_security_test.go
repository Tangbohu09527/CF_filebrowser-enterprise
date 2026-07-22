package http

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gtsteffaniak/filebrowser/backend/auth"
	"github.com/gtsteffaniak/filebrowser/backend/common/settings"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/filebrowser/backend/database/access"
	dbshare "github.com/gtsteffaniak/filebrowser/backend/database/share"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
	"github.com/gtsteffaniak/filebrowser/backend/indexing/iteminfo"
)

const (
	permissionShareSecret       = "permission-share-secret-content"
	permissionShareDeniedChild  = "permission-share-denied-child-content"
	permissionShareOutsideScope = "permission-share-outside-scope-content"
	permissionShareExternal     = "permission-share-external-content"
	permissionSharePasswordHash = "$2y$10$TFAmdCbyd/mEZDe5fUeZJu.MaJQXRTwdqb/IQV.eTn6dWrF58gCSe"
)

type permissionShareSecurityHarness struct {
	t          *testing.T
	sourcePath string
	router     http.Handler
}

func TestPermissionShareSecurityFailures(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)
	h := newPermissionShareSecurityHarness(t, sourcePath)

	t.Run("permission model exposes public read permissions", func(t *testing.T) {
		for _, name := range []string{"Browse", "Preview", "Download"} {
			name := name
			t.Run(name, func(t *testing.T) {
				requirePermissionSharePermissionField(t, name)
			})
		}
	})

	t.Run("public share route descriptors are complete and fail closed", func(t *testing.T) {
		cases := []struct {
			name           string
			path           string
			query          url.Values
			getUploadProbe bool
			want           publicShareRoute
		}{
			{name: "resource browse", path: "/resources", query: url.Values{"hash": {"route-hash"}, "path": {"/"}}, getUploadProbe: true, want: publicShareRoute{recognized: true, read: true, requirement: publicShareReadBrowse, targetMode: publicShareTargetPath}},
			{name: "resource missing probe path", path: "/resources", query: url.Values{"hash": {"route-hash"}}, want: publicShareRoute{recognized: true, read: true, requirement: publicShareReadBrowse, targetMode: publicShareTargetPath}},
			{name: "resource unrelated read parameter", path: "/resources", query: url.Values{"hash": {"route-hash"}, "path": {"/"}, "size": {"original"}}, want: publicShareRoute{recognized: true, read: true, requirement: publicShareReadBrowse, targetMode: publicShareTargetPath}},
			{name: "resource explicit content false", path: "/resources", query: url.Values{"hash": {"route-hash"}, "path": {"/"}, "content": {"false"}}, want: publicShareRoute{recognized: true, read: true, requirement: publicShareReadBrowse, targetMode: publicShareTargetPath}},
			{name: "resource explicit metadata false", path: "/resources", query: url.Values{"hash": {"route-hash"}, "path": {"/"}, "metadata": {"false"}}, want: publicShareRoute{recognized: true, read: true, requirement: publicShareReadBrowse, targetMode: publicShareTargetPath}},
			{name: "resource content", path: "/resources", query: url.Values{"content": {"true"}}, want: publicShareRoute{recognized: true, read: true, requirement: publicShareReadOriginalViewer, targetMode: publicShareTargetPath}},
			{name: "resource metadata", path: "/resources", query: url.Values{"metadata": {"true"}}, want: publicShareRoute{recognized: true, read: true, requirement: publicShareReadBrowse | publicShareReadViewer, targetMode: publicShareTargetPath}},
			{name: "resource items", path: "/resources/items", want: publicShareRoute{recognized: true, read: true, requirement: publicShareReadBrowse, targetMode: publicShareTargetPath}},
			{name: "download", path: "/resources/download", want: publicShareRoute{recognized: true, read: true, requirement: publicShareReadBrowse | publicShareReadDownload, targetMode: publicShareTargetFiles, skipFileInfo: true}},
			{name: "raw", path: "/raw", want: publicShareRoute{recognized: true, read: true, requirement: publicShareReadBrowse | publicShareReadDownload, targetMode: publicShareTargetFiles, skipFileInfo: true}},
			{name: "preview default", path: "/resources/preview", want: publicShareRoute{recognized: true, read: true, requirement: publicShareReadBrowse | publicShareReadThumbnail, targetMode: publicShareTargetPath, albumArt: true}},
			{name: "preview small", path: "/resources/preview", query: url.Values{"size": {"small"}}, want: publicShareRoute{recognized: true, read: true, requirement: publicShareReadBrowse | publicShareReadThumbnail, targetMode: publicShareTargetPath, albumArt: true}},
			{name: "preview large", path: "/resources/preview", query: url.Values{"size": {"large"}}, want: publicShareRoute{recognized: true, read: true, requirement: publicShareReadBrowse | publicShareReadViewer, targetMode: publicShareTargetPath, albumArt: true}},
			{name: "preview xlarge", path: "/resources/preview", query: url.Values{"size": {"xlarge"}}, want: publicShareRoute{recognized: true, read: true, requirement: publicShareReadBrowse | publicShareReadViewer, targetMode: publicShareTargetPath, albumArt: true}},
			{name: "preview original", path: "/resources/preview", query: url.Values{"size": {"original"}}, want: publicShareRoute{recognized: true, read: true, requirement: publicShareReadOriginalViewer, targetMode: publicShareTargetPath, albumArt: true}},
			{name: "share favicon", path: "/share/image", query: url.Values{"favicon": {"true"}}, want: publicShareRoute{recognized: true, read: true, requirement: publicShareReadBrowse | publicShareReadThumbnail, targetMode: publicShareTargetImage, skipFileInfo: true}},
			{name: "share banner", path: "/share/image", query: url.Values{"banner": {"true"}}, want: publicShareRoute{recognized: true, read: true, requirement: publicShareReadBrowse | publicShareReadThumbnail | publicShareReadViewer, targetMode: publicShareTargetImage, skipFileInfo: true}},
			{name: "media metadata", path: "/media/metadata", want: publicShareRoute{recognized: true, read: true, requirement: publicShareReadBrowse | publicShareReadViewer, targetMode: publicShareTargetPath}},
			{name: "media subtitles", path: "/media/subtitles", want: publicShareRoute{recognized: true, read: true, requirement: publicShareReadOriginalViewer, targetMode: publicShareTargetPath}},
			{name: "media lyrics", path: "/media/lyrics", want: publicShareRoute{recognized: true, read: true, requirement: publicShareReadOriginalViewer, targetMode: publicShareTargetPath}},
			{name: "OnlyOffice config", path: "/office/config", want: publicShareRoute{recognized: true, read: true, requirement: publicShareReadOriginalViewer, targetMode: publicShareTargetPath}},
		}
		for _, tc := range cases {
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				t.Run(tc.name+" "+method, func(t *testing.T) {
					route, err := publicShareRouteForRequest(method, tc.path, tc.query)
					if err != nil {
						t.Fatalf("unexpected descriptor error: %v", err)
					}
					want := tc.want
					want.uploadInitializationProbe = method == http.MethodGet && tc.getUploadProbe
					if route != want {
						t.Errorf("got descriptor %+v, want %+v", route, want)
					}
				})
			}
		}

		writeCases := []struct {
			name   string
			method string
			path   string
			want   publicShareRoute
		}{
			{name: "upload", method: http.MethodPost, path: "/resources", want: publicShareRoute{recognized: true, targetMode: publicShareTargetPath, skipFileInfo: true}},
			{name: "pause upload", method: http.MethodPost, path: "/resources/pause", want: publicShareRoute{recognized: true, targetMode: publicShareTargetPath, skipFileInfo: true}},
			{name: "put resource", method: http.MethodPut, path: "/resources", want: publicShareRoute{recognized: true, targetMode: publicShareTargetPath, skipFileInfo: true}},
			{name: "patch resource", method: http.MethodPatch, path: "/resources", want: publicShareRoute{recognized: true, targetMode: publicShareTargetPath, skipFileInfo: true}},
			{name: "delete resource", method: http.MethodDelete, path: "/resources", want: publicShareRoute{recognized: true, targetMode: publicShareTargetPath, skipFileInfo: true}},
			{name: "bulk delete", method: http.MethodDelete, path: "/resources/bulk", want: publicShareRoute{recognized: true, targetMode: publicShareTargetPath, skipFileInfo: true}},
			{name: "OnlyOffice GET callback", method: http.MethodGet, path: "/office/callback", want: publicShareRoute{recognized: true, targetMode: publicShareTargetPath, skipFileInfo: true}},
			{name: "OnlyOffice POST callback", method: http.MethodPost, path: "/office/callback", want: publicShareRoute{recognized: true, targetMode: publicShareTargetPath, skipFileInfo: true}},
		}
		for _, tc := range writeCases {
			t.Run(tc.name, func(t *testing.T) {
				route, err := publicShareRouteForRequest(tc.method, tc.path, nil)
				if err != nil {
					t.Fatalf("unexpected descriptor error: %v", err)
				}
				if route != tc.want || route.read || route.requirement != publicShareReadNone {
					t.Errorf("write route was classified as a read: got %+v, want %+v", route, tc.want)
				}
			})
		}

		nearMatches := []string{
			"/future/read",
			"/resources-extra",
			"/resources/items-extra",
			"/resources/download-extra",
			"/resources/preview-extra",
			"/raw-extra",
			"/share/image-extra",
			"/media/metadata-extra",
			"/office/config-extra",
		}
		for _, routePath := range nearMatches {
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				t.Run("fail closed "+method+" "+routePath, func(t *testing.T) {
					route, err := publicShareRouteForRequest(method, routePath, nil)
					if err != nil {
						t.Fatalf("unexpected descriptor error: %v", err)
					}
					if route != (publicShareRoute{}) {
						t.Errorf("near-match route was recognized: %+v", route)
					}
				})
			}
		}

		headCallback, err := publicShareRouteForRequest(http.MethodHead, "/office/callback", nil)
		if err != nil {
			t.Fatalf("HEAD OnlyOffice callback descriptor: %v", err)
		}
		if headCallback != (publicShareRoute{}) {
			t.Errorf("HEAD OnlyOffice callback must fail closed, got %+v", headCallback)
		}
	})

	t.Run("owner Browse revocation immediately blocks public reads", func(t *testing.T) {
		owner := h.newOwner(t, "browse-revocation-owner", users.Permissions{
			Browse:   true,
			Preview:  true,
			Download: true,
		})
		h.saveShare(t, owner, "browse-revocation-share", "/public", nil)

		requests := []permissionShareDownloadRequest{
			{
				name:          "resource listing",
				path:          "/public/api/resources",
				query:         url.Values{"hash": {"browse-revocation-share"}, "path": {"/"}},
				allowedStatus: http.StatusOK,
			},
			{
				name:          "file detail",
				path:          "/public/api/resources",
				query:         url.Values{"hash": {"browse-revocation-share"}, "path": {"/secret.txt"}},
				allowedStatus: http.StatusOK,
			},
			{
				name:          "items listing",
				path:          "/public/api/resources/items",
				query:         url.Values{"hash": {"browse-revocation-share"}, "path": {"/"}},
				allowedStatus: http.StatusOK,
			},
			{
				name:          "share info",
				path:          "/public/api/share/info",
				query:         url.Values{"hash": {"browse-revocation-share"}},
				allowedStatus: http.StatusOK,
			},
		}
		requests = append(requests, h.downloadRequestMatrix("browse-revocation-share")...)
		for _, request := range requests {
			response := h.request(http.MethodGet, request.path, request.query, nil, request.headers)
			requirePermissionShareReadAllowed(t, request.name+" before revocation", request, response)
		}

		setPermissionSharePermissionIfPresent(&owner.Permissions, "Browse", false)
		h.updateOwnerPermissions(t, owner)
		for _, request := range requests {
			response := h.request(http.MethodGet, request.path, request.query, nil, request.headers)
			assertPermissionShareReadDenied(t, request.name+" after revocation", response)
		}
	})

	t.Run("owner Preview revocation immediately blocks thumbnails and previews", func(t *testing.T) {
		owner := h.newOwner(t, "preview-revocation-owner", users.Permissions{Download: true})
		setPermissionSharePermissionIfPresent(&owner.Permissions, "Browse", true)
		setPermissionSharePermissionIfPresent(&owner.Permissions, "Preview", true)
		h.updateOwnerPermissions(t, owner)
		h.saveShare(t, owner, "preview-revocation-share", "/public", nil)

		for _, size := range []string{"small", "original"} {
			response := h.preview("preview-revocation-share", size)
			requirePermissionShareStatus(t, size+" preview before revocation", response, http.StatusOK)
			if response.Body.Len() == 0 {
				t.Fatalf("%s preview before revocation returned an empty body", size)
			}
		}

		setPermissionSharePermissionIfPresent(&owner.Permissions, "Preview", false)
		h.updateOwnerPermissions(t, owner)
		for _, size := range []string{"small", "large", "original"} {
			response := h.preview("preview-revocation-share", size)
			assertPermissionShareReadDenied(t, size+" preview after revocation", response)
		}
		headMetadata := h.request(http.MethodHead, "/public/api/media/metadata", url.Values{
			"hash": {"preview-revocation-share"},
			"path": {"/pixel.png"},
		}, nil, nil)
		assertPermissionShareReadDenied(t, "HEAD metadata after Preview revocation", headMetadata)
	})

	t.Run("owner Download revocation blocks every original file path", func(t *testing.T) {
		owner := h.newOwner(t, "download-revocation-owner", users.Permissions{Download: true})
		setPermissionSharePermissionIfPresent(&owner.Permissions, "Browse", true)
		setPermissionSharePermissionIfPresent(&owner.Permissions, "Preview", true)
		h.updateOwnerPermissions(t, owner)
		h.saveShare(t, owner, "download-revocation-share", "/public", nil)

		requests := h.downloadRequestMatrix("download-revocation-share")
		for _, request := range requests {
			response := h.request(http.MethodGet, request.path, request.query, nil, request.headers)
			requirePermissionShareReadAllowed(t, request.name+" before revocation", request, response)
		}

		setPermissionSharePermissionIfPresent(&owner.Permissions, "Download", false)
		h.updateOwnerPermissions(t, owner)
		for _, request := range requests {
			response := h.request(http.MethodGet, request.path, request.query, nil, request.headers)
			assertPermissionShareReadDenied(t, request.name+" after revocation", response)
		}
		headContent := h.request(http.MethodHead, "/public/api/resources", url.Values{
			"hash":    {"download-revocation-share"},
			"path":    {"/secret.txt"},
			"content": {"true"},
		}, nil, nil)
		assertPermissionShareReadDenied(t, "HEAD content after Download revocation", headContent)
	})

	t.Run("DisableDownload cannot be bypassed by original content paths", func(t *testing.T) {
		owner := h.newOwner(t, "disable-download-owner", users.Permissions{Download: true})
		setPermissionSharePermissionIfPresent(&owner.Permissions, "Browse", true)
		setPermissionSharePermissionIfPresent(&owner.Permissions, "Preview", true)
		h.updateOwnerPermissions(t, owner)
		h.saveShare(t, owner, "disable-download-share", "/public", func(common *dbshare.CommonShare) {
			common.DisableDownload = true
			common.Banner = url.Values{"source": {"source1"}, "path": {"/public/pixel.png"}}.Encode()
		})

		for _, request := range h.downloadRequestMatrix("disable-download-share") {
			response := h.request(http.MethodGet, request.path, request.query, nil, request.headers)
			assertPermissionShareReadDenied(t, request.name, response)
		}
		shareImageResponse := h.request(http.MethodGet, "/public/api/share/image", url.Values{
			"hash":   {"disable-download-share"},
			"banner": {"true"},
		}, nil, nil)
		assertPermissionShareReadDenied(t, "share image serving original", shareImageResponse)
	})

	t.Run("download limit applies before dynamically served originals", func(t *testing.T) {
		owner := h.newOwner(t, "dynamic-original-limit-owner", users.Permissions{
			Browse:   true,
			Preview:  true,
			Download: true,
		})
		link := h.saveShare(t, owner, "dynamic-original-limit-share", "/public", func(common *dbshare.CommonShare) {
			common.DownloadsLimit = 1
			common.Banner = url.Values{"source": {"source1"}, "path": {"/public/pixel.png"}}.Encode()
		})
		link.Downloads = 1

		small := h.preview("dynamic-original-limit-share", "small")
		assertPermissionShareReadDenied(t, "small preview original after download limit", small)
		shareImage := h.request(http.MethodGet, "/public/api/share/image", url.Values{
			"hash":   {"dynamic-original-limit-share"},
			"banner": {"true"},
		}, nil, nil)
		assertPermissionShareReadDenied(t, "share image original after download limit", shareImage)
	})

	t.Run("content reads consume the download limit atomically", func(t *testing.T) {
		owner := h.newOwner(t, "content-limit-concurrency-owner", users.Permissions{
			Browse: true, Preview: true, Download: true,
		})
		link := h.saveShare(t, owner, "content-limit-concurrency-share", "/public", func(common *dbshare.CommonShare) {
			common.DownloadsLimit = 1
		})

		originalFileInfoFaster := FileInfoFasterFunc
		entered := make(chan struct{}, 2)
		release := make(chan struct{})
		FileInfoFasterFunc = func(options utils.FileOptions, accessStorage *access.Storage, user *users.User, shareStorage *dbshare.Storage) (*iteminfo.ExtendedFileInfo, error) {
			entered <- struct{}{}
			<-release
			return originalFileInfoFaster(options, accessStorage, user, shareStorage)
		}
		defer func() { FileInfoFasterFunc = originalFileInfoFaster }()

		invoke := func(result chan<- *httptest.ResponseRecorder) {
			query := url.Values{
				"hash": {link.Hash}, "path": {"/secret.txt"}, "content": {"true"},
			}
			request := httptest.NewRequest(http.MethodGet, "/public/api/resources?"+query.Encode(), nil)
			response := httptest.NewRecorder()
			h.router.ServeHTTP(response, request)
			result <- response
		}
		results := make(chan *httptest.ResponseRecorder, 2)
		go invoke(results)
		go invoke(results)
		for range 2 {
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				close(release)
				t.Fatal("concurrent content reads did not reach the file lookup barrier")
			}
		}
		close(release)

		responses := []*httptest.ResponseRecorder{<-results, <-results}
		successes := 0
		denials := 0
		for _, response := range responses {
			switch response.Code {
			case http.StatusOK:
				successes++
				if !strings.Contains(response.Body.String(), permissionShareSecret) {
					t.Fatalf("successful content response omitted authorized body: %q", response.Body.String())
				}
			case http.StatusForbidden:
				denials++
				if strings.Contains(response.Body.String(), permissionShareSecret) {
					t.Fatalf("denied content response exposed body: %q", response.Body.String())
				}
			default:
				t.Fatalf("concurrent content response status: got %d, want 200 or 403", response.Code)
			}
		}
		if successes != 1 || denials != 1 {
			t.Fatalf("concurrent content results: successes=%d denials=%d", successes, denials)
		}
		link.Mu.Lock()
		downloads := link.Downloads
		link.Mu.Unlock()
		if downloads != 1 {
			t.Fatalf("concurrent content download count: got %d, want 1", downloads)
		}
	})

	t.Run("content read rejects a target replaced after authorization", func(t *testing.T) {
		owner := h.newOwner(t, "content-target-replacement-owner", users.Permissions{
			Browse: true, Preview: true, Download: true,
		})
		h.saveShare(t, owner, "content-target-replacement-share", "/public", nil)
		targetPath := filepath.Join(sourcePath, "public", "secret.txt")
		originalContent, err := os.ReadFile(targetPath)
		if err != nil {
			t.Fatal(err)
		}
		outsidePath := filepath.Join(t.TempDir(), "outside-secret.txt")
		const outsideSecret = "PUBLIC-CONTENT-TARGET-REPLACEMENT-SECRET"
		if err := os.WriteFile(outsidePath, []byte(outsideSecret), 0o644); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_ = os.Remove(targetPath)
			_ = os.WriteFile(targetPath, originalContent, 0o644)
		}()

		originalFileInfoFaster := FileInfoFasterFunc
		replaced := false
		FileInfoFasterFunc = func(options utils.FileOptions, accessStorage *access.Storage, user *users.User, shareStorage *dbshare.Storage) (*iteminfo.ExtendedFileInfo, error) {
			if !replaced {
				replaced = true
				if err := os.Remove(targetPath); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outsidePath, targetPath); err != nil {
					t.Skipf("symlink fixture is unavailable: %v", err)
				}
			}
			return originalFileInfoFaster(options, accessStorage, user, shareStorage)
		}
		defer func() { FileInfoFasterFunc = originalFileInfoFaster }()

		response := h.request(http.MethodGet, "/public/api/resources", url.Values{
			"hash": {"content-target-replacement-share"}, "path": {"/secret.txt"}, "content": {"true"},
		}, nil, nil)
		if response.Code != http.StatusForbidden {
			t.Fatalf("replaced content target status: got %d, want %d", response.Code, http.StatusForbidden)
		}
		if strings.Contains(response.Body.String(), outsideSecret) {
			t.Fatalf("replaced content target leaked outside data: %q", response.Body.String())
		}
	})

	t.Run("original preview rejects a target replaced after file lookup", func(t *testing.T) {
		owner := h.newOwner(t, "preview-target-replacement-owner", users.Permissions{
			Browse: true, Preview: true, Download: true,
		})
		h.saveShare(t, owner, "preview-target-replacement-share", "/public", nil)
		targetPath := filepath.Join(sourcePath, "public", "pixel.png")
		originalContent, err := os.ReadFile(targetPath)
		if err != nil {
			t.Fatal(err)
		}
		outsidePath := filepath.Join(t.TempDir(), "outside-preview.png")
		const outsideSecret = "PUBLIC-PREVIEW-TARGET-REPLACEMENT-SECRET"
		if err := os.WriteFile(outsidePath, []byte(outsideSecret), 0o644); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_ = os.Remove(targetPath)
			_ = os.WriteFile(targetPath, originalContent, 0o644)
		}()

		originalFileInfoFaster := FileInfoFasterFunc
		replaced := false
		FileInfoFasterFunc = func(options utils.FileOptions, accessStorage *access.Storage, user *users.User, shareStorage *dbshare.Storage) (*iteminfo.ExtendedFileInfo, error) {
			fileInfo, infoErr := originalFileInfoFaster(options, accessStorage, user, shareStorage)
			if infoErr == nil && !replaced {
				replaced = true
				if err := os.Remove(targetPath); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outsidePath, targetPath); err != nil {
					t.Skipf("symlink fixture is unavailable: %v", err)
				}
			}
			return fileInfo, infoErr
		}
		defer func() { FileInfoFasterFunc = originalFileInfoFaster }()

		response := h.request(http.MethodGet, "/public/api/resources/preview", url.Values{
			"hash": {"preview-target-replacement-share"}, "path": {"/pixel.png"}, "size": {"original"},
		}, nil, nil)
		if response.Code != http.StatusForbidden {
			t.Fatalf("replaced preview target status: got %d, want %d", response.Code, http.StatusForbidden)
		}
		if strings.Contains(response.Body.String(), outsideSecret) {
			t.Fatalf("replaced preview target leaked outside data: %q", response.Body.String())
		}
	})

	t.Run("DisableFileViewer and DisableThumbnails remain stricter", func(t *testing.T) {
		owner := h.newOwner(t, "strict-share-flags-owner", users.Permissions{Download: true})
		setPermissionSharePermissionIfPresent(&owner.Permissions, "Browse", true)
		setPermissionSharePermissionIfPresent(&owner.Permissions, "Preview", true)
		h.updateOwnerPermissions(t, owner)

		h.saveShare(t, owner, "disable-viewer-share", "/public", func(common *dbshare.CommonShare) {
			common.DisableFileViewer = true
			common.EnableOnlyOffice = true
			common.Banner = url.Values{"source": {"source1"}, "path": {"/public/pixel.png"}}.Encode()
		})
		contentResponse := h.request(http.MethodGet, "/public/api/resources", url.Values{
			"hash":    {"disable-viewer-share"},
			"path":    {"/secret.txt"},
			"content": {"true"},
		}, nil, nil)
		assertPermissionShareReadDenied(t, "DisableFileViewer content viewer", contentResponse)
		originalResponse := h.preview("disable-viewer-share", "original")
		assertPermissionShareReadDenied(t, "DisableFileViewer original viewer", originalResponse)
		for _, size := range []string{"large", "xlarge"} {
			classificationRequest := httptest.NewRequest(http.MethodGet, "/resources/preview?size="+size, nil)
			if got := publicShareReadRequirementForRequest(classificationRequest); got&publicShareReadViewer == 0 || got&publicShareReadThumbnail != 0 {
				t.Errorf("%s preview classified as %v, want Viewer", size, got)
				continue
			}
			derivedViewer := h.preview("disable-viewer-share", size)
			assertPermissionShareReadDenied(t, "DisableFileViewer "+size+" derived viewer", derivedViewer)
		}
		viewerRequests := []permissionShareDownloadRequest{
			{
				name:  "resource metadata viewer",
				path:  "/public/api/resources",
				query: url.Values{"hash": {"disable-viewer-share"}, "path": {"/pixel.png"}, "metadata": {"true"}},
			},
			{
				name:  "media metadata viewer",
				path:  "/public/api/media/metadata",
				query: url.Values{"hash": {"disable-viewer-share"}, "path": {"/pixel.png"}},
			},
			{
				name:  "media subtitles viewer",
				path:  "/public/api/media/subtitles",
				query: url.Values{"hash": {"disable-viewer-share"}, "path": {"/secret.txt"}, "name": {"secret.srt"}, "embedded": {"false"}},
			},
			{
				name:  "media lyrics viewer",
				path:  "/public/api/media/lyrics",
				query: url.Values{"hash": {"disable-viewer-share"}, "path": {"/secret.txt"}},
			},
			{
				name:  "OnlyOffice viewer",
				path:  "/public/api/office/config",
				query: url.Values{"hash": {"disable-viewer-share"}, "path": {"/secret.txt"}},
			},
		}
		for _, request := range viewerRequests {
			response := h.request(http.MethodGet, request.path, request.query, nil, nil)
			assertPermissionShareReadDenied(t, "DisableFileViewer "+request.name, response)
		}
		viewerImage := h.request(http.MethodGet, "/public/api/share/image", url.Values{
			"hash":   {"disable-viewer-share"},
			"banner": {"true"},
		}, nil, nil)
		assertPermissionShareReadDenied(t, "DisableFileViewer share image", viewerImage)

		h.saveShare(t, owner, "disable-thumbnails-share", "/public", func(common *dbshare.CommonShare) {
			common.DisableThumbnails = true
			common.Banner = url.Values{"source": {"source1"}, "path": {"/public/pixel.png"}}.Encode()
		})
		thumbnailResponse := h.preview("disable-thumbnails-share", "small")
		assertPermissionShareReadDenied(t, "DisableThumbnails small preview", thumbnailResponse)
		shareImageResponse := h.request(http.MethodGet, "/public/api/share/image", url.Values{
			"hash":   {"disable-thumbnails-share"},
			"banner": {"true"},
		}, nil, nil)
		assertPermissionShareReadDenied(t, "DisableThumbnails share image", shareImageResponse)
		thumbnailDisabledLink, err := store.Share.GetByHash("disable-thumbnails-share")
		if err != nil {
			t.Fatal(err)
		}
		thumbnailDisabledAccess := calculatePublicShareAccess(thumbnailDisabledLink, owner)
		for _, size := range []string{"large", "xlarge"} {
			classificationRequest := httptest.NewRequest(http.MethodGet, "/resources/preview?size="+size, nil)
			requirement := publicShareReadRequirementForRequest(classificationRequest)
			if requirement&publicShareReadViewer == 0 || requirement&publicShareReadThumbnail != 0 {
				t.Errorf("%s preview classified as %v, want Viewer", size, requirement)
				continue
			}
			if !thumbnailDisabledAccess.allows(requirement) {
				t.Errorf("DisableThumbnails unexpectedly disabled %s Viewer", size)
			}
		}
		originalViewer := h.preview("disable-thumbnails-share", "original")
		requirePermissionShareStatus(t, "DisableThumbnails original viewer", originalViewer, http.StatusOK)
	})

	t.Run("all Disable flag combinations keep independent capability classes", func(t *testing.T) {
		owner := &users.User{Permissions: users.Permissions{
			Share: true, Browse: true, Preview: true, Download: true,
		}}
		for mask := 0; mask < 8; mask++ {
			disableThumbnails := mask&1 != 0
			disableViewer := mask&2 != 0
			disableDownload := mask&4 != 0
			t.Run(fmt.Sprintf("thumbnail=%t viewer=%t download=%t", disableThumbnails, disableViewer, disableDownload), func(t *testing.T) {
				link := &dbshare.Link{
					CommonShare: dbshare.CommonShare{
						ShareType:         "normal",
						DisableThumbnails: disableThumbnails,
						DisableFileViewer: disableViewer,
						DisableDownload:   disableDownload,
					},
					CapabilityVersion:   dbshare.CurrentCapabilityVersion,
					CreatorCapabilities: dbshare.CapabilitiesFromPermissions(owner.Permissions),
				}
				access := calculatePublicShareAccess(link, owner)
				checks := []struct {
					name        string
					requirement publicShareReadRequirement
					want        bool
				}{
					{name: "thumbnail", requirement: publicShareReadBrowse | publicShareReadThumbnail, want: !disableThumbnails},
					{name: "viewer", requirement: publicShareReadBrowse | publicShareReadViewer, want: !disableViewer},
					{name: "download", requirement: publicShareReadBrowse | publicShareReadDownload, want: !disableDownload},
					{name: "original viewer", requirement: publicShareReadOriginalViewer, want: !disableViewer && !disableDownload},
				}
				for _, check := range checks {
					if got := access.allows(check.requirement); got != check.want {
						t.Errorf("%s capability: got %v, want %v", check.name, got, check.want)
					}
				}
				frontend := access.frontendCapabilities()
				if frontend.Preview != (!disableThumbnails || !disableViewer) {
					t.Errorf("frontend preview: got %v", frontend.Preview)
				}
			})
		}
	})

	t.Run("public read routes are exact and fail closed", func(t *testing.T) {
		owner := h.newOwner(t, "route-classification-owner", users.Permissions{
			Browse:   true,
			Preview:  true,
			Download: true,
		})
		h.saveShare(t, owner, "route-classification-share", "/public", nil)

		for _, route := range []string{"/public/api/future/read", "/public/api/resources/items-extra"} {
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				response := h.request(method, route, url.Values{
					"hash": {"route-classification-share"},
					"path": {"/secret.txt"},
				}, nil, nil)
				assertPermissionShareReadDenied(t, method+" "+route, response)
				if strings.Contains(response.Body.String(), "unexpected handler execution") {
					t.Fatalf("%s %s reached an unclassified public handler", method, route)
				}
			}
		}
	})

	t.Run("public paths reject ambiguous and platform-specific escapes", func(t *testing.T) {
		owner := h.newOwner(t, "strict-path-owner", users.Permissions{Browse: true, Download: true})
		h.saveShare(t, owner, "strict-path-share", "/public", nil)

		cases := []struct {
			name     string
			rawQuery string
		}{
			{name: "cleaned traversal", rawQuery: "hash=strict-path-share&file=%2Fallowed%2F..%2Fsecret.txt"},
			{name: "backslash traversal", rawQuery: "hash=strict-path-share&file=%5C..%5Coutside-scope.txt"},
			{name: "double encoded traversal", rawQuery: "hash=strict-path-share&file=%252e%252e%252foutside-scope.txt"},
			{name: "UNC path", rawQuery: "hash=strict-path-share&file=%5C%5Cserver%5Cshare"},
			{name: "drive path", rawQuery: "hash=strict-path-share&file=C%3A%5Coutside-scope.txt"},
			{name: "device path", rawQuery: "hash=strict-path-share&file=%5C%5C%3F%5CC%3A%5Coutside-scope.txt"},
			{name: "NUL", rawQuery: "hash=strict-path-share&file=%2Fsecret.txt%00suffix"},
			{name: "malformed percent escape", rawQuery: "hash=strict-path-share&file=%ZZ"},
			{name: "invalid semicolon query", rawQuery: "hash=strict-path-share&file=%2Fsecret.txt;file=%2Foutside-scope.txt"},
			{name: "multiple files with traversal", rawQuery: "hash=strict-path-share&file=%2Fallowed.txt&file=%2F..%2Foutside-scope.txt"},
			{name: "multiple path values", rawQuery: "hash=strict-path-share&path=%2Fsecret.txt&path=%2F..%2Foutside-scope.txt"},
		}
		if runtime.GOOS == "windows" {
			cases = append(cases,
				struct {
					name     string
					rawQuery string
				}{name: "alternate data stream", rawQuery: "hash=strict-path-share&file=%2Fsecret.txt%3Astream"},
			)
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				route := "/public/api/resources/download"
				if tc.name == "multiple path values" {
					route = "/public/api/resources"
				}
				response := h.requestRawQuery(http.MethodGet, route, tc.rawQuery, nil, nil)
				assertPermissionShareReadDenied(t, tc.name, response)
			})
		}

		if err := store.Access.DenyUser(h.sourcePath, "/public/denied.txt", owner.Username); err != nil {
			t.Fatalf("deny repeated target: %v", err)
		}
		mixed := h.requestRawQuery(http.MethodGet, "/public/api/resources/download",
			"hash=strict-path-share&file=%2Fallowed.txt&file=%2Fdenied.txt", nil, nil)
		assertPermissionShareReadDenied(t, "multiple files with denied member", mixed)

		special := h.download("strict-path-share", "/special #+comma,[1].txt")
		requirePermissionShareStatus(t, "special filename", special, http.StatusOK)
		if special.Body.String() != "permission-share-special-name" {
			t.Fatalf("special filename returned %q", special.Body.String())
		}
	})

	t.Run("public targets stay inside source share root Scope and Access Rule", func(t *testing.T) {
		owner := h.newOwner(t, "symlink-owner", users.Permissions{Browse: true, Preview: true, Download: true})
		h.saveShare(t, owner, "symlink-share", "/public", nil)

		externalDir := t.TempDir()
		externalPath := filepath.Join(externalDir, "external.txt")
		if err := os.WriteFile(externalPath, []byte(permissionShareExternal), 0o644); err != nil {
			t.Fatal(err)
		}
		links := []struct {
			name   string
			target string
		}{
			{name: "source-outside-link.txt", target: externalPath},
			{name: "share-outside-link.txt", target: filepath.Join(h.sourcePath, "outside-scope.txt")},
			{name: "denied-alias.txt", target: filepath.Join(h.sourcePath, "public", "denied.txt")},
		}
		for _, link := range links {
			if err := os.Symlink(link.target, filepath.Join(h.sourcePath, "public", link.name)); err != nil {
				t.Skipf("symlink creation is unavailable: %v", err)
			}
		}
		if err := store.Access.DenyUser(h.sourcePath, "/public/denied.txt", owner.Username); err != nil {
			t.Fatalf("deny canonical symlink target: %v", err)
		}

		for _, link := range links {
			response := h.download("symlink-share", "/"+link.name)
			assertPermissionShareReadDenied(t, link.name, response)
			if strings.Contains(response.Body.String(), permissionShareExternal) {
				t.Fatalf("%s leaked Source-external content", link.name)
			}
		}

		resourceList := h.request(http.MethodGet, "/public/api/resources", url.Values{
			"hash": {"symlink-share"},
			"path": {"/"},
		}, nil, nil)
		requirePermissionShareStatus(t, "filtered resource list", resourceList, http.StatusOK)
		itemsList := h.request(http.MethodGet, "/public/api/resources/items", url.Values{
			"hash": {"symlink-share"},
			"path": {"/"},
		}, nil, nil)
		requirePermissionShareStatus(t, "filtered items list", itemsList, http.StatusOK)
		metadataList := h.request(http.MethodGet, "/public/api/media/metadata", url.Values{
			"hash":     {"symlink-share"},
			"path":     {"/"},
			"albumArt": {"true"},
		}, nil, nil)
		requirePermissionShareStatus(t, "filtered metadata list", metadataList, http.StatusOK)
		for _, link := range links {
			if strings.Contains(resourceList.Body.String(), link.name) || strings.Contains(itemsList.Body.String(), link.name) ||
				strings.Contains(metadataList.Body.String(), link.name) {
				t.Errorf("directory listing exposed unauthorized symlink %q", link.name)
			}
		}

		cacheLink := filepath.Join(h.sourcePath, "public", "retargeted-link.txt")
		if err := os.Symlink(filepath.Join(h.sourcePath, "public", "allowed.txt"), cacheLink); err != nil {
			t.Fatal(err)
		}
		allowed := h.download("symlink-share", "/retargeted-link.txt")
		requirePermissionShareStatus(t, "symlink before retarget", allowed, http.StatusOK)
		if err := os.Remove(cacheLink); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(h.sourcePath, "outside-scope.txt"), cacheLink); err != nil {
			t.Fatal(err)
		}
		retargeted := h.download("symlink-share", "/retargeted-link.txt")
		assertPermissionShareReadDenied(t, "symlink after retarget", retargeted)

		if runtime.GOOS == "windows" {
			casePath := filepath.Join(h.sourcePath, "public", "CaseSecret.txt")
			if err := os.WriteFile(casePath, []byte("permission-share-case-secret"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := store.Access.DenyUser(h.sourcePath, "/public/CaseSecret.txt", owner.Username); err != nil {
				t.Fatal(err)
			}
			caseAlias := h.download("symlink-share", "/casesecret.txt")
			assertPermissionShareReadDenied(t, "case-insensitive Access Rule alias", caseAlias)
		}
	})

	t.Run("Access Rule changes take effect on the next request", func(t *testing.T) {
		owner := h.newOwner(t, "access-cycle-owner", users.Permissions{Browse: true, Download: true})
		h.saveShare(t, owner, "access-cycle-share", "/public", nil)

		first := h.download("access-cycle-share", "/allowed.txt")
		requirePermissionShareStatus(t, "Access Rule initial allow", first, http.StatusOK)
		if err := store.Access.DenyUser(h.sourcePath, "/public/allowed.txt", owner.Username); err != nil {
			t.Fatal(err)
		}
		denied := h.download("access-cycle-share", "/allowed.txt")
		assertPermissionShareReadDenied(t, "Access Rule deny", denied)
		removed, err := store.Access.RemoveDenyUser(h.sourcePath, "/public/allowed.txt", owner.Username)
		if err != nil || !removed {
			t.Fatalf("remove Access Rule deny: removed=%v err=%v", removed, err)
		}
		restored := h.download("access-cycle-share", "/allowed.txt")
		requirePermissionShareStatus(t, "Access Rule restored allow", restored, http.StatusOK)
	})

	t.Run("stored share root fails closed", func(t *testing.T) {
		owner := h.newOwner(t, "stored-path-owner", users.Permissions{Browse: true, Download: true})
		h.saveShare(t, owner, "empty-share-root", "", nil)
		emptyRoot := h.download("empty-share-root", "/secret.txt")
		assertPermissionShareReadDenied(t, "empty stored share root", emptyRoot)

		traversal := h.saveShare(t, owner, "traversal-share-root", "/public", nil)
		traversal.Path = "/public/../"
		traversalRoot := h.download("traversal-share-root", "/secret.txt")
		assertPermissionShareReadDenied(t, "traversal stored share root", traversalRoot)
	})

	if runtime.GOOS == "windows" {
		t.Run("Scope casing remains compatible while Access Rule casing stays enforced", func(t *testing.T) {
			owner := h.newOwner(t, "scope-case-owner", users.Permissions{Browse: true, Download: true})
			owner.Scopes = []users.SourceScope{{Name: h.sourcePath, Scope: "/PUBLIC"}}
			if err := store.Users.Update(owner, true, "Scopes"); err != nil {
				t.Fatal(err)
			}
			h.saveShare(t, owner, "scope-case-share", "/public", nil)

			allowed := h.download("scope-case-share", "/allowed.txt")
			requirePermissionShareStatus(t, "case-insensitive Scope", allowed, http.StatusOK)
			if err := store.Access.DenyUser(h.sourcePath, "/public/allowed.txt", owner.Username); err != nil {
				t.Fatal(err)
			}
			denied := h.download("scope-case-share", "/ALLOWED.TXT")
			assertPermissionShareReadDenied(t, "case-insensitive canonical Access Rule", denied)
		})
	}

	t.Run("upload shares do not acquire Browse Preview or Download", func(t *testing.T) {
		owner := h.newOwner(t, "upload-read-owner", users.Permissions{Share: true, Create: true})
		setPermissionSharePermissionIfPresent(&owner.Permissions, "Browse", false)
		setPermissionSharePermissionIfPresent(&owner.Permissions, "Preview", false)
		setPermissionSharePermissionIfPresent(&owner.Permissions, "Download", false)
		h.updateOwnerPermissions(t, owner)

		body, err := json.Marshal(dbshare.CreateBody{CommonShare: dbshare.CommonShare{
			Source:    "source1",
			Path:      "/public",
			ShareType: "upload",
		}})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/api/share", bytes.NewReader(body))
		response := httptest.NewRecorder()
		status, err := sharePostHandler(response, request, &requestContext{user: owner})
		if err != nil || status != http.StatusOK {
			t.Fatalf("create upload share: expected status %d, got %d (err=%v, body=%s)", http.StatusOK, status, err, permissionShareResponseBody(response))
		}
		var created struct {
			Hash string `json:"hash"`
		}
		if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
			t.Fatalf("decode upload share response: %v", err)
		}
		if created.Hash == "" {
			t.Fatal("create upload share returned an empty hash")
		}
		link, err := store.Share.GetByHash(created.Hash)
		if err != nil {
			t.Fatalf("load upload share: %v", err)
		}
		if !link.AllowCreate {
			t.Error("upload share did not retain its required create capability")
		}
		probe := h.request(http.MethodGet, "/public/api/resources", url.Values{
			"hash": {created.Hash},
			"path": {"/"},
		}, nil, nil)
		requirePermissionShareStatus(t, "authenticated upload initialization probe", probe, http.StatusNotImplemented)
		assertPermissionShareNoBrowseInformation(t, "authenticated upload initialization probe", probe, h.sourcePath)
		headProbe := h.request(http.MethodHead, "/public/api/resources", url.Values{
			"hash": {created.Hash},
			"path": {"/"},
		}, nil, nil)
		assertPermissionShareReadDenied(t, "upload initialization HEAD", headProbe)

		requests := []struct {
			name    string
			path    string
			query   url.Values
			headers map[string]string
		}{
			{
				name:  "items browse",
				path:  "/public/api/resources/items",
				query: url.Values{"hash": {created.Hash}, "path": {"/"}},
			},
			{
				name:  "content viewer",
				path:  "/public/api/resources",
				query: url.Values{"hash": {created.Hash}, "path": {"/secret.txt"}, "content": {"true"}},
			},
			{
				name:  "preview",
				path:  "/public/api/resources/preview",
				query: url.Values{"hash": {created.Hash}, "path": {"/pixel.png"}, "size": {"small"}},
			},
			{
				name:  "original viewer",
				path:  "/public/api/resources/preview",
				query: url.Values{"hash": {created.Hash}, "path": {"/pixel.png"}, "size": {"original"}},
			},
			{
				name:  "download",
				path:  "/public/api/resources/download",
				query: url.Values{"hash": {created.Hash}, "file": {"/secret.txt"}},
			},
			{
				name:  "raw",
				path:  "/public/api/raw",
				query: url.Values{"hash": {created.Hash}, "file": {"/secret.txt"}},
			},
			{
				name:    "Range",
				path:    "/public/api/resources/download",
				query:   url.Values{"hash": {created.Hash}, "file": {"/secret.txt"}},
				headers: map[string]string{"Range": "bytes=0-3"},
			},
			{
				name:  "media subtitles",
				path:  "/public/api/media/subtitles",
				query: url.Values{"hash": {created.Hash}, "path": {"/secret.txt"}, "name": {"secret.srt"}, "embedded": {"false"}},
			},
			{
				name:  "media metadata",
				path:  "/public/api/media/metadata",
				query: url.Values{"hash": {created.Hash}, "path": {"/pixel.png"}},
			},
			{
				name:  "OnlyOffice viewer",
				path:  "/public/api/office/config",
				query: url.Values{"hash": {created.Hash}, "path": {"/secret.txt"}},
			},
		}
		for _, request := range requests {
			response := h.request(http.MethodGet, request.path, request.query, nil, request.headers)
			assertPermissionShareReadDenied(t, "upload share "+request.name, response)
			headResponse := h.request(http.MethodHead, request.path, request.query, nil, request.headers)
			assertPermissionShareReadDenied(t, "upload share HEAD "+request.name, headResponse)
		}
	})

	t.Run("password protected upload share keeps the 501 initialization contract without Browse leakage", func(t *testing.T) {
		owner := h.newOwner(t, "password-upload-owner", users.Permissions{Create: true, Modify: true})
		link := h.saveShare(t, owner, "password-upload-share", "/public", func(common *dbshare.CommonShare) {
			common.ShareType = "upload"
			common.AllowCreate = true
			common.AllowReplacements = false
			common.HasPassword = true
		})
		link.PasswordHash = permissionSharePasswordHash
		if err := store.Share.Save(link); err != nil {
			t.Fatalf("save password protected upload share: %v", err)
		}

		shareInfo := h.request(http.MethodGet, "/public/api/share/info", url.Values{
			"hash": {link.Hash},
		}, nil, nil)
		requirePermissionShareStatus(t, "upload page share info", shareInfo, http.StatusOK)
		assertPermissionShareNoBrowseInformation(t, "upload page share info", shareInfo, h.sourcePath)
		var info map[string]any
		if err := json.Unmarshal(shareInfo.Body.Bytes(), &info); err != nil {
			t.Fatalf("decode upload share info: %v", err)
		}
		if info["shareType"] != "upload" || info["hasPassword"] != true {
			t.Fatalf("upload share info lacks initialization fields: %s", permissionShareResponseBody(shareInfo))
		}

		correctPassword := map[string]string{"X-SHARE-PASSWORD": "password"}
		probeQuery := url.Values{"hash": {link.Hash}, "path": {"/"}}
		correctProbe := h.request(http.MethodGet, "/public/api/resources", probeQuery, nil, correctPassword)
		requirePermissionShareStatus(t, "correct upload share password", correctProbe, http.StatusNotImplemented)
		assertPermissionShareNoBrowseInformation(t, "correct upload share password", correctProbe, h.sourcePath)

		nonProbeRequests := []struct {
			name    string
			query   url.Values
			headers map[string]string
		}{
			{
				name:  "missing path",
				query: url.Values{"hash": {link.Hash}},
			},
			{
				name:  "explicit content false",
				query: url.Values{"hash": {link.Hash}, "path": {"/"}, "content": {"false"}},
			},
			{
				name:  "explicit metadata false",
				query: url.Values{"hash": {link.Hash}, "path": {"/"}, "metadata": {"false"}},
			},
			{
				name:  "unrelated original size",
				query: url.Values{"hash": {link.Hash}, "path": {"/"}, "size": {"original"}},
			},
			{
				name:    "Range",
				query:   probeQuery,
				headers: map[string]string{"Range": "bytes=0-3"},
			},
			{
				name:  "invalid path",
				query: url.Values{"hash": {link.Hash}, "path": {"/../secret.txt"}},
			},
		}
		for _, request := range nonProbeRequests {
			headers := map[string]string{"X-SHARE-PASSWORD": "password"}
			for name, value := range request.headers {
				headers[name] = value
			}
			response := h.request(http.MethodGet, "/public/api/resources", request.query, nil, headers)
			requirePermissionShareStatus(t, "upload initialization "+request.name, response, http.StatusForbidden)
			assertPermissionShareNoBrowseInformation(t, "upload initialization "+request.name, response, h.sourcePath)
		}

		wrongProbe := h.request(http.MethodGet, "/public/api/resources", probeQuery, nil, map[string]string{
			"X-SHARE-PASSWORD": "wrong-password",
		})
		requirePermissionShareStatus(t, "wrong upload share password", wrongProbe, http.StatusUnauthorized)
		assertPermissionShareNoBrowseInformation(t, "wrong upload share password", wrongProbe, h.sourcePath)

		items := h.request(http.MethodGet, "/public/api/resources/items", probeQuery, nil, correctPassword)
		requirePermissionShareStatus(t, "upload share items enumeration", items, http.StatusForbidden)
		assertPermissionShareNoBrowseInformation(t, "upload share items enumeration", items, h.sourcePath)

		content := h.request(http.MethodGet, "/public/api/resources", url.Values{
			"hash":    {link.Hash},
			"path":    {"/secret.txt"},
			"content": {"true"},
		}, nil, correctPassword)
		requirePermissionShareStatus(t, "upload share content read", content, http.StatusForbidden)
		assertPermissionShareNoBrowseInformation(t, "upload share content read", content, h.sourcePath)

		const uploadedContent = "password protected upload content"
		const uploadedName = "password-upload-created.txt"
		upload := h.request(http.MethodPost, "/public/api/resources", url.Values{
			"hash": {link.Hash},
			"path": {"/" + uploadedName},
		}, strings.NewReader(uploadedContent), correctPassword)
		requirePermissionShareStatus(t, "password protected upload", upload, http.StatusOK)
		uploaded, err := os.ReadFile(filepath.Join(h.sourcePath, "public", uploadedName))
		if err != nil {
			t.Fatalf("read password protected upload: %v", err)
		}
		if string(uploaded) != uploadedContent {
			t.Fatalf("password protected upload content: got %q, want %q", uploaded, uploadedContent)
		}

		const existingName = "password-upload-existing.txt"
		const existingContent = "existing protected upload content"
		existingPath := filepath.Join(h.sourcePath, "public", existingName)
		if err := os.WriteFile(existingPath, []byte(existingContent), 0o644); err != nil {
			t.Fatalf("write existing protected upload: %v", err)
		}
		replacement := h.request(http.MethodPost, "/public/api/resources", url.Values{
			"hash":     {link.Hash},
			"path":     {"/" + existingName},
			"override": {"true"},
		}, strings.NewReader("replacement must be rejected"), correctPassword)
		requirePermissionShareStatus(t, "password protected replacement", replacement, http.StatusForbidden)
		preserved, err := os.ReadFile(existingPath)
		if err != nil {
			t.Fatalf("read preserved protected upload: %v", err)
		}
		if string(preserved) != existingContent {
			t.Fatalf("disabled replacement changed protected upload: got %q, want %q", preserved, existingContent)
		}
	})

	t.Run("directory shares enforce Scope and Access Rule for each child", func(t *testing.T) {
		t.Run("Access Rule", func(t *testing.T) {
			owner := h.newOwner(t, "child-rule-owner", users.Permissions{Download: true})
			setPermissionSharePermissionIfPresent(&owner.Permissions, "Browse", true)
			h.updateOwnerPermissions(t, owner)
			h.saveShare(t, owner, "child-rule-share", "/public", nil)
			if err := store.Access.DenyUser(h.sourcePath, "/public/denied.txt", owner.Username); err != nil {
				t.Fatalf("deny shared child by Access Rule: %v", err)
			}

			allowed := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
				"hash": {"child-rule-share"},
				"path": {"/allowed.txt"},
				"file": {"/allowed.txt"},
			}, nil, nil)
			requirePermissionShareStatus(t, "allowed sibling", allowed, http.StatusOK)
			if allowed.Body.String() != "permission-share-allowed-child" {
				t.Fatalf("allowed sibling: got body %q", allowed.Body.String())
			}

			denied := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
				"hash": {"child-rule-share"},
				"path": {"/allowed.txt"},
				"file": {"/denied.txt"},
			}, nil, nil)
			assertPermissionShareReadDenied(t, "Access Rule denied child", denied)

			directoryArchive := h.download("child-rule-share", "/")
			assertPermissionShareReadDenied(t, "directory archive containing Access Rule denied child", directoryArchive)
		})

		t.Run("Scope", func(t *testing.T) {
			owner := h.newOwner(t, "child-scope-owner", users.Permissions{Download: true})
			setPermissionSharePermissionIfPresent(&owner.Permissions, "Browse", true)
			h.updateOwnerPermissions(t, owner)
			h.saveShare(t, owner, "child-scope-share", "/", nil)

			allowedBeforeRevocation := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
				"hash": {"child-scope-share"},
				"file": {"/outside-scope.txt"},
			}, nil, nil)
			requirePermissionShareStatus(t, "root child before Scope revocation", allowedBeforeRevocation, http.StatusOK)
			if allowedBeforeRevocation.Body.String() != permissionShareOutsideScope {
				t.Fatalf("root child before Scope revocation: got body %q", allowedBeforeRevocation.Body.String())
			}

			owner.Scopes = []users.SourceScope{{Name: h.sourcePath, Scope: "/public/allowed"}}
			if err := store.Users.Update(owner, true, "Scopes"); err != nil {
				t.Fatalf("narrow share owner Scope: %v", err)
			}
			insideScope := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
				"hash": {"child-scope-share"},
				"file": {"/public/allowed/decoy.txt"},
			}, nil, nil)
			requirePermissionShareStatus(t, "child inside narrowed owner Scope", insideScope, http.StatusOK)
			if insideScope.Body.String() != "permission-share-scope-decoy" {
				t.Fatalf("child inside narrowed owner Scope: got body %q", insideScope.Body.String())
			}

			outsideScope := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
				"hash": {"child-scope-share"},
				"path": {"/decoy.txt"},
				"file": {"/outside-scope.txt"},
			}, nil, nil)
			assertPermissionShareReadDenied(t, "child outside current owner Scope", outsideScope)
		})
	})

	t.Run("directory archives use one fixed authorized member set", func(t *testing.T) {
		owner := h.newOwner(t, "archive-manifest-owner", users.Permissions{Browse: true, Download: true})
		for _, algorithm := range []string{"zip", "tar.gz"} {
			t.Run(algorithm, func(t *testing.T) {
				directoryName := "archive-drift-" + strings.ReplaceAll(algorithm, ".", "-")
				root := filepath.Join(h.sourcePath, "public", directoryName)
				lateDir := filepath.Join(root, "z-late")
				if err := os.MkdirAll(lateDir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "a-trigger.bin"), permissionShareNoise(1024*1024), 0o644); err != nil {
					t.Fatal(err)
				}
				hash := "archive-manifest-" + strings.ReplaceAll(algorithm, ".", "-")
				h.saveShare(t, owner, hash, "/public/"+directoryName, nil)

				request := httptest.NewRequest(http.MethodGet, "/public/api/resources/download?"+url.Values{
					"hash": {hash},
					"file": {"/"},
					"algo": {algorithm},
				}.Encode(), nil)
				recorder := httptest.NewRecorder()
				var mutationErr error
				writer := &permissionShareMutatingRecorder{
					ResponseRecorder: recorder,
					mutate: func() {
						mutationErr = os.WriteFile(filepath.Join(lateDir, "late-secret.txt"), []byte(permissionShareDeniedChild), 0o644)
					},
				}
				h.router.ServeHTTP(writer, request)
				if mutationErr != nil {
					t.Fatalf("create late archive member: %v", mutationErr)
				}
				requirePermissionShareStatus(t, "fixed "+algorithm+" archive manifest", recorder, http.StatusOK)
				var entries map[string]struct{}
				if algorithm == "zip" {
					entries = permissionShareZipEntries(t, recorder.Body.Bytes())
				} else {
					entries = permissionShareTarEntries(t, recorder.Body.Bytes())
				}
				if _, ok := entries[directoryName+"/z-late/late-secret.txt"]; ok {
					t.Fatalf("%s archive included a member created after authorization", algorithm)
				}
			})
		}
	})

	t.Run("archive tokens are bound to share and original authorized members", func(t *testing.T) {
		owner := h.newOwner(t, "archive-token-owner", users.Permissions{Browse: true, Download: true})
		if err := os.MkdirAll(settings.DownloadCacheDir(), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, dir := range []string{
			"token-a", "token-b", "token-stale", "token-revoke", "token-root-a", "token-root-b", "token-access",
		} {
			path := filepath.Join(h.sourcePath, "public", dir)
			if err := os.MkdirAll(path, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(path, "member.bin"), permissionShareNoise(64*1024), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		h.saveShare(t, owner, "archive-token-a-share", "/public/token-a", nil)
		h.saveShare(t, owner, "archive-token-b-share", "/public/token-b", nil)
		h.saveShare(t, owner, "archive-token-stale-share", "/public/token-stale", nil)
		h.saveShare(t, owner, "archive-token-revoke-share", "/public/token-revoke", nil)
		h.saveShare(t, owner, "archive-token-root-share", "/public", nil)
		h.saveShare(t, owner, "archive-token-access-share", "/public/token-access", nil)

		first := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
			"hash": {"archive-token-a-share"},
			"file": {"/"},
		}, nil, map[string]string{"Range": "bytes=0-31"})
		requirePermissionShareStatus(t, "create share-bound archive token", first, http.StatusPartialContent)
		token := first.Header().Get("X-Archive-Token")
		if token == "" {
			t.Fatal("archive Range response did not return X-Archive-Token")
		}
		crossShare := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
			"hash":         {"archive-token-b-share"},
			"file":         {"/"},
			"archiveToken": {token},
		}, nil, map[string]string{"Range": "bytes=32-63"})
		assertPermissionShareReadDenied(t, "cross-share archive token replay", crossShare)

		formatFirst := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
			"hash": {"archive-token-b-share"},
			"file": {"/"},
			"algo": {"zip"},
		}, nil, map[string]string{"Range": "bytes=0-31"})
		requirePermissionShareStatus(t, "create format-bound archive token", formatFirst, http.StatusPartialContent)
		formatToken := formatFirst.Header().Get("X-Archive-Token")
		formatReplay := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
			"hash":         {"archive-token-b-share"},
			"file":         {"/"},
			"algo":         {"tar.gz"},
			"archiveToken": {formatToken},
		}, nil, map[string]string{"Range": "bytes=32-63"})
		assertPermissionShareReadDenied(t, "archive token format drift", formatReplay)

		if err := store.Access.AllowUser(h.sourcePath, "/public/token-root-a/member.bin", owner.Username); err != nil {
			t.Fatal(err)
		}
		rootFirst := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
			"hash": {"archive-token-root-share"},
			"file": {"/token-root-a"},
		}, nil, map[string]string{"Range": "bytes=0-31"})
		requirePermissionShareStatus(t, "create root-bound archive token", rootFirst, http.StatusPartialContent)
		rootToken := rootFirst.Header().Get("X-Archive-Token")
		if err := store.Access.DenyUser(h.sourcePath, "/public/token-root-a", owner.Username); err != nil {
			t.Fatal(err)
		}
		rootReplay := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
			"hash":         {"archive-token-root-share"},
			"file":         {"/token-root-b"},
			"archiveToken": {rootToken},
		}, nil, map[string]string{"Range": "bytes=32-63"})
		assertPermissionShareReadDenied(t, "archive token with changed top-level target", rootReplay)

		staleFirst := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
			"hash": {"archive-token-stale-share"},
			"file": {"/"},
		}, nil, map[string]string{"Range": "bytes=0-31"})
		requirePermissionShareStatus(t, "create stale-member archive token", staleFirst, http.StatusPartialContent)
		staleToken := staleFirst.Header().Get("X-Archive-Token")
		if staleToken == "" {
			t.Fatal("stale-member Range response did not return X-Archive-Token")
		}
		if err := os.Remove(filepath.Join(h.sourcePath, "public", "token-stale", "member.bin")); err != nil {
			t.Fatal(err)
		}
		staleReplay := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
			"hash":         {"archive-token-stale-share"},
			"file":         {"/"},
			"archiveToken": {staleToken},
		}, nil, map[string]string{"Range": "bytes=32-63"})
		assertPermissionShareReadDenied(t, "archive token after member deletion", staleReplay)

		revokeFirst := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
			"hash": {"archive-token-revoke-share"},
			"file": {"/"},
		}, nil, map[string]string{"Range": "bytes=0-31"})
		requirePermissionShareStatus(t, "create permission-lifecycle archive token", revokeFirst, http.StatusPartialContent)
		revokeToken := revokeFirst.Header().Get("X-Archive-Token")
		if revokeToken == "" {
			t.Fatal("permission-lifecycle Range response did not return X-Archive-Token")
		}
		owner.Permissions.Download = false
		h.updateOwnerPermissions(t, owner)
		revoked := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
			"hash":         {"archive-token-revoke-share"},
			"file":         {"/"},
			"archiveToken": {revokeToken},
		}, nil, map[string]string{"Range": "bytes=32-63"})
		assertPermissionShareReadDenied(t, "archive token during owner revocation", revoked)

		owner.Permissions.Download = true
		h.updateOwnerPermissions(t, owner)
		oldToken := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
			"hash":         {"archive-token-revoke-share"},
			"file":         {"/"},
			"archiveToken": {revokeToken},
		}, nil, map[string]string{"Range": "bytes=32-63"})
		assertPermissionShareReadDenied(t, "archive token created before owner revocation", oldToken)
		restored := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
			"hash": {"archive-token-revoke-share"},
			"file": {"/"},
		}, nil, map[string]string{"Range": "bytes=0-31"})
		requirePermissionShareStatus(t, "new archive after owner regrant", restored, http.StatusPartialContent)

		accessFirst := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
			"hash": {"archive-token-access-share"},
			"file": {"/"},
		}, nil, map[string]string{"Range": "bytes=0-31"})
		requirePermissionShareStatus(t, "create Access lifecycle archive token", accessFirst, http.StatusPartialContent)
		accessToken := accessFirst.Header().Get("X-Archive-Token")
		if err := store.Access.DenyUser(h.sourcePath, "/public/token-access/member.bin", owner.Username); err != nil {
			t.Fatal(err)
		}
		accessRevoked := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
			"hash":         {"archive-token-access-share"},
			"file":         {"/"},
			"archiveToken": {accessToken},
		}, nil, map[string]string{"Range": "bytes=32-63"})
		assertPermissionShareReadDenied(t, "archive token during Access Rule revocation", accessRevoked)
		removed, err := store.Access.RemoveDenyUser(h.sourcePath, "/public/token-access/member.bin", owner.Username)
		if err != nil || !removed {
			t.Fatalf("remove archive Access Rule deny: removed=%v err=%v", removed, err)
		}
		oldAccessToken := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
			"hash":         {"archive-token-access-share"},
			"file":         {"/"},
			"archiveToken": {accessToken},
		}, nil, map[string]string{"Range": "bytes=32-63"})
		assertPermissionShareReadDenied(t, "archive token created before Access Rule revocation", oldAccessToken)
		newAccessArchive := h.request(http.MethodGet, "/public/api/resources/download", url.Values{
			"hash": {"archive-token-access-share"},
			"file": {"/"},
		}, nil, map[string]string{"Range": "bytes=0-31"})
		requirePermissionShareStatus(t, "new archive after Access Rule reallow", newAccessArchive, http.StatusPartialContent)
	})

	t.Run("non-owner cannot update another share policy by hash", func(t *testing.T) {
		owner := h.newOwner(t, "policy-owner", users.Permissions{Api: true, Share: true, Browse: true, Preview: true, Download: true})
		attacker := h.newOwner(t, "policy-attacker", users.Permissions{Api: true, Share: true, Browse: true, Preview: true, Download: true})
		admin := h.newOwner(t, "policy-admin", users.Permissions{Api: true, Admin: true, Share: true, Browse: true, Preview: true, Download: true})
		link := h.saveShare(t, owner, "victim-policy-share", "/public", func(common *dbshare.CommonShare) {
			common.Title = "owner policy"
		})

		ownerResponse := h.updateSharePolicy(t, owner, dbshare.CreateBody{
			Hash: "victim-policy-share",
			CommonShare: dbshare.CommonShare{
				ShareType: "normal",
				Title:     "owner updated policy",
			},
		})
		requirePermissionShareStatus(t, "owner policy update", ownerResponse, http.StatusOK)

		attackerShare := h.saveShare(t, attacker, "attacker-policy-share", "/public", nil)
		attackerOwnResponse := h.updateSharePolicy(t, attacker, dbshare.CreateBody{
			Hash: attackerShare.Hash,
			CommonShare: dbshare.CommonShare{
				ShareType: "normal",
				Title:     "attacker own policy",
			},
		})
		requirePermissionShareStatus(t, "attacker own policy update", attackerOwnResponse, http.StatusOK)
		attackerStored, err := store.Share.GetByHash(attackerShare.Hash)
		if err != nil {
			t.Fatalf("reload attacker share: %v", err)
		}
		if attackerStored.Title != "attacker own policy" {
			t.Fatalf("attacker could not update own policy: title=%q", attackerStored.Title)
		}

		response := h.updateSharePolicy(t, attacker, dbshare.CreateBody{
			Hash: "victim-policy-share",
			CommonShare: dbshare.CommonShare{
				ShareType:         "normal",
				Title:             "attacker policy",
				DisableDownload:   true,
				DisableFileViewer: true,
			},
		})
		assertPermissionShareStatus(t, "non-owner policy update", response, http.StatusForbidden)

		stored, err := store.Share.GetByHash(link.Hash)
		if err != nil {
			t.Fatalf("reload victim share: %v", err)
		}
		if stored.Title != "owner updated policy" || stored.DisableDownload || stored.DisableFileViewer {
			t.Errorf("non-owner changed victim policy: title=%q disableDownload=%v disableFileViewer=%v", stored.Title, stored.DisableDownload, stored.DisableFileViewer)
		}

		adminResponse := h.updateSharePolicy(t, admin, dbshare.CreateBody{
			Hash: link.Hash,
			CommonShare: dbshare.CommonShare{
				ShareType: "normal",
				Title:     "admin policy",
			},
		})
		requirePermissionShareStatus(t, "admin policy update", adminResponse, http.StatusOK)
		stored, err = store.Share.GetByHash(link.Hash)
		if err != nil {
			t.Fatalf("reload admin-updated share: %v", err)
		}
		if stored.Title != "admin policy" {
			t.Fatalf("admin could not update share policy: title=%q", stored.Title)
		}
	})

	t.Run("share cache hit re-evaluates current owner permission", func(t *testing.T) {
		owner := h.newOwner(t, "cache-owner", users.Permissions{Browse: true, Download: true})
		h.saveShare(t, owner, "cache-permission-share", "/public", nil)

		allowed := h.download("cache-permission-share", "/secret.txt")
		requirePermissionShareStatus(t, "first request before cache hit", allowed, http.StatusOK)
		if allowed.Body.String() != permissionShareSecret {
			t.Fatalf("first request before cache hit: got body %q", allowed.Body.String())
		}
		cachedBefore, err := store.Share.GetByHash("cache-permission-share")
		if err != nil {
			t.Fatalf("prime share cache: %v", err)
		}

		setPermissionSharePermissionIfPresent(&owner.Permissions, "Download", false)
		h.updateOwnerPermissions(t, owner)
		cachedAfter, err := store.Share.GetByHash("cache-permission-share")
		if err != nil {
			t.Fatalf("read cached share after owner update: %v", err)
		}
		if cachedBefore != cachedAfter {
			t.Fatal("share cache fixture did not return the cached Link instance")
		}

		denied := h.download("cache-permission-share", "/secret.txt")
		assertPermissionShareReadDenied(t, "cached share after owner revocation", denied)
	})

	t.Run("owner permission grant revoke and regrant take effect immediately", func(t *testing.T) {
		owner := h.newOwner(t, "permission-cycle-owner", users.Permissions{Browse: true, Download: true})
		h.saveShare(t, owner, "permission-cycle-share", "/public", nil)

		first := h.download("permission-cycle-share", "/secret.txt")
		requirePermissionShareStatus(t, "initial grant", first, http.StatusOK)
		if first.Body.String() != permissionShareSecret {
			t.Fatalf("initial grant: got body %q", first.Body.String())
		}

		setPermissionSharePermissionIfPresent(&owner.Permissions, "Download", false)
		h.updateOwnerPermissions(t, owner)
		revoked := h.download("permission-cycle-share", "/secret.txt")
		assertPermissionShareReadDenied(t, "revoked permission", revoked)

		setPermissionSharePermissionIfPresent(&owner.Permissions, "Download", true)
		h.updateOwnerPermissions(t, owner)
		restored := h.download("permission-cycle-share", "/secret.txt")
		assertPermissionShareStatus(t, "restored permission", restored, http.StatusOK)
		if restored.Body.String() != permissionShareSecret {
			t.Fatalf("restored permission: got body %q", restored.Body.String())
		}
	})

	t.Run("upload share replacement prohibition does not regress", func(t *testing.T) {
		owner := h.newOwner(t, "no-replacement-owner", users.Permissions{Create: true, Modify: true})
		h.saveShare(t, owner, "no-replacement-share", "/public", func(common *dbshare.CommonShare) {
			common.ShareType = "upload"
			common.AllowCreate = true
			common.AllowReplacements = false
		})

		target := filepath.Join(h.sourcePath, "public", "no-replacement.txt")
		const original = "original upload content"
		if err := os.WriteFile(target, []byte(original), 0o644); err != nil {
			t.Fatal(err)
		}
		response := h.request(http.MethodPost, "/public/api/resources", url.Values{
			"hash":     {"no-replacement-share"},
			"path":     {"/no-replacement.txt"},
			"override": {"true"},
		}, strings.NewReader("unauthorized replacement"), nil)
		assertPermissionShareStatus(t, "disabled upload replacement", response, http.StatusForbidden)
		content, err := os.ReadFile(target)
		if err != nil {
			t.Fatalf("read protected upload target: %v", err)
		}
		if string(content) != original {
			t.Errorf("disabled upload replacement changed file: got %q, want %q", content, original)
		}
	})
}

func newPermissionShareSecurityHarness(t *testing.T, sourcePath string) *permissionShareSecurityHarness {
	t.Helper()

	files := map[string][]byte{
		filepath.Join(sourcePath, "public", "secret.txt"):              []byte(permissionShareSecret),
		filepath.Join(sourcePath, "public", "allowed.txt"):             []byte("permission-share-allowed-child"),
		filepath.Join(sourcePath, "public", "denied.txt"):              []byte(permissionShareDeniedChild),
		filepath.Join(sourcePath, "outside-scope.txt"):                 []byte(permissionShareOutsideScope),
		filepath.Join(sourcePath, "public", "allowed", "decoy.txt"):    []byte("permission-share-scope-decoy"),
		filepath.Join(sourcePath, "public", "special #+comma,[1].txt"): []byte("permission-share-special-name"),
	}
	if err := os.MkdirAll(filepath.Join(sourcePath, "public", "allowed"), 0o755); err != nil {
		t.Fatal(err)
	}
	for path, content := range files {
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatalf("write security fixture %s: %v", path, err)
		}
	}
	pixel, err := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourcePath, "public", "pixel.png"), pixel, 0o644); err != nil {
		t.Fatal(err)
	}

	previousConfigAuth := config.Auth
	previousSettingsAuth := settings.Config.Auth
	testAuth := settings.Auth{Key: "permission-share-security-test-key"}
	config.Auth = testAuth
	settings.Config.Auth = testAuth
	t.Cleanup(func() {
		config.Auth = previousConfigAuth
		settings.Config.Auth = previousSettingsAuth
	})

	publicAPI := http.NewServeMux()
	publicAPI.HandleFunc("GET /resources", withHashFile(publicGetResourceHandler))
	publicAPI.HandleFunc("GET /resources/items", withHashFile(publicItemsGetHandler))
	publicAPI.HandleFunc("POST /resources", withHashFile(publicUploadHandler))
	publicAPI.HandleFunc("GET /resources/download", withHashFile(publicDownloadHandler))
	publicAPI.HandleFunc("GET /resources/preview", withTimeout(30*time.Second, withHashFileHelper(publicPreviewHandler)))
	publicAPI.HandleFunc("GET /raw", withHashFile(publicDownloadHandler))
	publicAPI.HandleFunc("GET /share/info", withOrWithoutUser(shareInfoHandler))
	publicAPI.HandleFunc("GET /share/image", withHashFile(getShareImage))
	publicAPI.HandleFunc("GET /media/metadata", withHashFile(publicMetadataHandler))
	publicAPI.HandleFunc("GET /media/subtitles", withHashFile(publicSubtitlesHandler))
	publicAPI.HandleFunc("GET /media/lyrics", withHashFile(publicLyricsHandler))
	publicAPI.HandleFunc("GET /office/config", withHashFile(onlyofficeClientConfigGetHandler))
	probeHandler := func(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
		return renderJSON(w, r, map[string]string{"status": "unexpected handler execution"})
	}
	publicAPI.HandleFunc("GET /future/read", withHashFile(probeHandler))
	publicAPI.HandleFunc("GET /resources/items-extra", withHashFile(probeHandler))

	api := http.NewServeMux()
	api.HandleFunc("POST /share", withPermShare(sharePostHandler))

	router := http.NewServeMux()
	router.Handle("/public/api/", http.StripPrefix("/public/api", publicAPI))
	router.Handle("/api/", http.StripPrefix("/api", api))

	return &permissionShareSecurityHarness{t: t, sourcePath: sourcePath, router: router}
}

func (h *permissionShareSecurityHarness) newOwner(t *testing.T, username string, permissions users.Permissions) *users.User {
	t.Helper()
	permissions.Share = true
	owner := &users.User{
		Username:    username,
		Permissions: permissions,
		Scopes: []users.SourceScope{
			{Name: h.sourcePath, Scope: "/"},
		},
	}
	if err := store.Users.Save(owner, false, false); err != nil {
		t.Fatalf("save share owner %s: %v", username, err)
	}
	if owner.ID == 0 {
		t.Fatalf("saved share owner %s has no ID", username)
	}
	return owner
}

func (h *permissionShareSecurityHarness) updateOwnerPermissions(t *testing.T, owner *users.User) {
	t.Helper()
	if err := store.Users.Update(owner, true, "Permissions"); err != nil {
		t.Fatalf("update share owner %s permissions: %v", owner.Username, err)
	}
}

func (h *permissionShareSecurityHarness) saveShare(t *testing.T, owner *users.User, hash, path string, configure func(*dbshare.CommonShare)) *dbshare.Link {
	t.Helper()
	common := dbshare.CommonShare{
		Source:    h.sourcePath,
		Path:      path,
		ShareType: "normal",
	}
	if configure != nil {
		configure(&common)
	}
	link := &dbshare.Link{
		Hash:                hash,
		UserID:              owner.ID,
		CommonShare:         common,
		CapabilityVersion:   dbshare.CurrentCapabilityVersion,
		CreatorCapabilities: dbshare.CapabilitiesFromPermissions(owner.Permissions),
	}
	if err := store.Share.Save(link); err != nil {
		t.Fatalf("save share %s: %v", hash, err)
	}
	return link
}

func (h *permissionShareSecurityHarness) updateSharePolicy(t *testing.T, user *users.User, body dbshare.CreateBody) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	name := "permission-share-policy-" + user.Username + "-" + utils.InsecureRandomIdentifier(4)
	token, metadata, err := auth.MakeSignedTokenAPI(user, name, time.Hour, user.Permissions, false)
	if err != nil {
		t.Fatalf("create policy token for %s: %v", user.Username, err)
	}
	if err := store.Users.AddApiToken(user.ID, name, token, metadata); err != nil {
		t.Fatalf("persist policy token metadata for %s: %v", user.Username, err)
	}
	if err := store.Access.AddApiToken(token, user.ID); err != nil {
		t.Fatalf("persist policy token mapping for %s: %v", user.Username, err)
	}
	return h.request(http.MethodPost, "/api/share", nil, bytes.NewReader(payload), map[string]string{
		"Authorization": "Bearer " + token,
		"Content-Type":  "application/json",
	})
}

func (h *permissionShareSecurityHarness) request(method, path string, query url.Values, body io.Reader, headers map[string]string) *httptest.ResponseRecorder {
	h.t.Helper()
	if len(query) > 0 {
		path += "?" + query.Encode()
	}
	request := httptest.NewRequest(method, path, body)
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	h.router.ServeHTTP(response, request)
	return response
}

func (h *permissionShareSecurityHarness) requestRawQuery(method, path, rawQuery string, body io.Reader, headers map[string]string) *httptest.ResponseRecorder {
	h.t.Helper()
	request := httptest.NewRequest(method, path, body)
	request.URL.RawQuery = rawQuery
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	h.router.ServeHTTP(response, request)
	return response
}

func (h *permissionShareSecurityHarness) preview(hash, size string) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.previewPath(hash, "/pixel.png", size)
}

func (h *permissionShareSecurityHarness) previewPath(hash, path, size string) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.request(http.MethodGet, "/public/api/resources/preview", url.Values{
		"hash": {hash},
		"path": {path},
		"size": {size},
	}, nil, nil)
}

func (h *permissionShareSecurityHarness) download(hash, file string) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.request(http.MethodGet, "/public/api/resources/download", url.Values{
		"hash": {hash},
		"file": {file},
	}, nil, nil)
}

type permissionShareDownloadRequest struct {
	name          string
	path          string
	query         url.Values
	headers       map[string]string
	allowedStatus int
}

func (h *permissionShareSecurityHarness) downloadRequestMatrix(hash string) []permissionShareDownloadRequest {
	return []permissionShareDownloadRequest{
		{
			name:          "download",
			path:          "/public/api/resources/download",
			query:         url.Values{"hash": {hash}, "file": {"/secret.txt"}},
			allowedStatus: http.StatusOK,
		},
		{
			name:          "raw",
			path:          "/public/api/raw",
			query:         url.Values{"hash": {hash}, "file": {"/secret.txt"}},
			allowedStatus: http.StatusOK,
		},
		{
			name:          "Range",
			path:          "/public/api/resources/download",
			query:         url.Values{"hash": {hash}, "file": {"/secret.txt"}},
			headers:       map[string]string{"Range": "bytes=0-3"},
			allowedStatus: http.StatusPartialContent,
		},
		{
			name:          "content viewer",
			path:          "/public/api/resources",
			query:         url.Values{"hash": {hash}, "path": {"/secret.txt"}, "content": {"true"}},
			allowedStatus: http.StatusOK,
		},
		{
			name:          "small preview serving original",
			path:          "/public/api/resources/preview",
			query:         url.Values{"hash": {hash}, "path": {"/pixel.png"}, "size": {"small"}},
			allowedStatus: http.StatusOK,
		},
		{
			name:          "original viewer",
			path:          "/public/api/resources/preview",
			query:         url.Values{"hash": {hash}, "path": {"/pixel.png"}, "size": {"original"}},
			allowedStatus: http.StatusOK,
		},
	}
}

func requirePermissionSharePermissionField(t *testing.T, name string) {
	t.Helper()
	field, ok := reflect.TypeOf(users.Permissions{}).FieldByName(name)
	if !ok {
		t.Fatalf("security contract cannot be exercised: users.Permissions.%s is missing", name)
	}
	if field.Type.Kind() != reflect.Bool {
		t.Fatalf("users.Permissions.%s must be bool, got %s", name, field.Type)
	}
}

func setPermissionSharePermissionIfPresent(permissions *users.Permissions, name string, allowed bool) bool {
	value := reflect.ValueOf(permissions)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return false
	}
	field := value.Elem().FieldByName(name)
	if !field.IsValid() || field.Kind() != reflect.Bool || !field.CanSet() {
		return false
	}
	field.SetBool(allowed)
	return true
}

func permissionShareNoise(size int) []byte {
	data := make([]byte, size)
	state := uint32(0x9e3779b9)
	for i := range data {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		data[i] = byte(state)
	}
	return data
}

type permissionShareMutatingRecorder struct {
	*httptest.ResponseRecorder
	once   sync.Once
	mutate func()
}

func (w *permissionShareMutatingRecorder) Write(data []byte) (int, error) {
	w.once.Do(w.mutate)
	return w.ResponseRecorder.Write(data)
}

func permissionShareZipEntries(t *testing.T, data []byte) map[string]struct{} {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("parse public share ZIP: %v", err)
	}
	entries := make(map[string]struct{}, len(reader.File))
	for _, file := range reader.File {
		entries[file.Name] = struct{}{}
	}
	return entries
}

func permissionShareTarEntries(t *testing.T, data []byte) map[string]struct{} {
	t.Helper()
	gzipReader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("open public share TAR.GZ: %v", err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	entries := make(map[string]struct{})
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("parse public share TAR.GZ: %v", err)
		}
		entries[header.Name] = struct{}{}
	}
	return entries
}

func requirePermissionShareReadAllowed(t *testing.T, scenario string, request permissionShareDownloadRequest, response *httptest.ResponseRecorder) {
	t.Helper()
	requirePermissionShareStatus(t, scenario, response, request.allowedStatus)
	switch request.name {
	case "resource listing", "items listing":
		if !strings.Contains(response.Body.String(), "allowed.txt") {
			t.Fatalf("%s did not return the expected directory item: body=%s", scenario, permissionShareResponseBody(response))
		}
	case "file detail":
		if !strings.Contains(response.Body.String(), `"name":"secret.txt"`) {
			t.Fatalf("%s did not return the expected file metadata: body=%s", scenario, permissionShareResponseBody(response))
		}
	case "share info":
		if !strings.Contains(response.Body.String(), `"shareType":"normal"`) {
			t.Fatalf("%s did not return normal share info: body=%s", scenario, permissionShareResponseBody(response))
		}
	case "download", "raw":
		if response.Body.String() != permissionShareSecret {
			t.Fatalf("%s: got body %q", scenario, response.Body.String())
		}
	case "Range":
		if response.Body.String() != permissionShareSecret[:4] {
			t.Fatalf("%s: got range body %q", scenario, response.Body.String())
		}
		if !strings.HasPrefix(response.Header().Get("Content-Range"), "bytes 0-3/") {
			t.Fatalf("%s: missing expected Content-Range header", scenario)
		}
	case "content viewer":
		if !strings.Contains(response.Body.String(), permissionShareSecret) {
			t.Fatalf("%s did not return the expected content: body=%s", scenario, permissionShareResponseBody(response))
		}
	case "small preview serving original", "original viewer":
		if response.Body.Len() == 0 {
			t.Fatalf("%s returned an empty original body", scenario)
		}
	}
}

func assertPermissionShareReadDenied(t *testing.T, scenario string, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusForbidden && response.Code != http.StatusNotFound {
		t.Errorf("%s: expected safe status 403 or 404, got %d; body=%s", scenario, response.Code, permissionShareResponseBody(response))
	}
	for _, sensitive := range []string{
		permissionShareSecret,
		permissionShareDeniedChild,
		permissionShareOutsideScope,
		permissionShareExternal,
		"secret.txt",
		"denied.txt",
		"outside-scope.txt",
	} {
		if strings.Contains(response.Body.String(), sensitive) {
			t.Errorf("%s leaked %q in the response body: %s", scenario, sensitive, permissionShareResponseBody(response))
		}
	}
	for _, header := range []string{"Content-Range", "Content-Disposition", "ETag", "Last-Modified"} {
		if value := response.Header().Get(header); value != "" {
			t.Errorf("%s leaked %s=%q", scenario, header, value)
		}
	}
}

func assertPermissionShareNoBrowseInformation(t *testing.T, scenario string, response *httptest.ResponseRecorder, sensitiveValues ...string) {
	t.Helper()
	body := response.Body.Bytes()
	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("%s returned a non-JSON response: %v; body=%s", scenario, err, permissionShareResponseBody(response))
	}
	if response.Code >= http.StatusBadRequest {
		errorPayload, ok := payload.(map[string]any)
		if !ok {
			t.Fatalf("%s returned a non-object error response: %s", scenario, permissionShareResponseBody(response))
		}
		for key := range errorPayload {
			if key != "status" && key != "message" {
				t.Errorf("%s returned unexpected error field %q: %s", scenario, key, permissionShareResponseBody(response))
			}
		}
		status, ok := errorPayload["status"].(float64)
		if !ok || int(status) != response.Code {
			t.Errorf("%s error envelope status=%v, HTTP status=%d", scenario, errorPayload["status"], response.Code)
		}
	}

	forbiddenKeys := map[string]struct{}{
		"canonicalPath":  {},
		"children":       {},
		"count":          {},
		"fileCount":      {},
		"files":          {},
		"indexPath":      {},
		"items":          {},
		"logicalPath":    {},
		"name":           {},
		"parentDirItems": {},
		"path":           {},
		"realPath":       {},
		"requestedPath":  {},
		"scopedPath":     {},
		"size":           {},
		"source":         {},
		"sourceURL":      {},
		"total":          {},
	}
	allSensitiveValues := append([]string{
		permissionShareSecret,
		permissionShareDeniedChild,
		permissionShareOutsideScope,
		permissionShareExternal,
		"secret.txt",
		"allowed.txt",
		"denied.txt",
		"outside-scope.txt",
	}, sensitiveValues...)
	var inspect func(any)
	inspect = func(value any) {
		switch typed := value.(type) {
		case map[string]any:
			for key, nested := range typed {
				if _, forbidden := forbiddenKeys[key]; forbidden {
					t.Errorf("%s leaked Browse field %q: %s", scenario, key, permissionShareResponseBody(response))
				}
				inspect(nested)
			}
		case []any:
			for _, nested := range typed {
				inspect(nested)
			}
		case string:
			for _, sensitive := range allSensitiveValues {
				if sensitive != "" && strings.Contains(typed, sensitive) {
					t.Errorf("%s leaked %q: %s", scenario, sensitive, permissionShareResponseBody(response))
				}
			}
		}
	}
	inspect(payload)
	for _, header := range []string{"Content-Range", "Content-Disposition", "ETag", "Last-Modified"} {
		if value := response.Header().Get(header); value != "" {
			t.Errorf("%s leaked %s=%q", scenario, header, value)
		}
	}
}

func requirePermissionShareStatus(t *testing.T, scenario string, response *httptest.ResponseRecorder, want int) {
	t.Helper()
	if response.Code != want {
		t.Fatalf("%s: expected status %d, got %d; body=%s", scenario, want, response.Code, permissionShareResponseBody(response))
	}
}

func assertPermissionShareStatus(t *testing.T, scenario string, response *httptest.ResponseRecorder, want int) {
	t.Helper()
	if response.Code != want {
		t.Errorf("%s: expected status %d, got %d; body=%s", scenario, want, response.Code, permissionShareResponseBody(response))
	}
}

func permissionShareResponseBody(response *httptest.ResponseRecorder) string {
	const limit = 256
	body := response.Body.String()
	if len(body) > limit {
		body = body[:limit] + "..."
	}
	return strings.ReplaceAll(body, "\n", "\\n")
}
