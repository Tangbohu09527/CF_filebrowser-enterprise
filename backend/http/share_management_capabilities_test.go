package http

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	dbshare "github.com/gtsteffaniak/filebrowser/backend/database/share"
	"github.com/gtsteffaniak/filebrowser/backend/database/users"
)

var managementShareCapabilityNames = []string{
	"browse",
	"preview",
	"download",
	"thumbnail",
	"viewer",
	"create",
	"modify",
	"delete",
	"replace",
}

func TestManagementShareCapabilityContract(t *testing.T) {
	sourcePath := setupResourcePutTestEnv(t)
	h := newPermissionShareSecurityHarness(t, sourcePath)
	fullPermissions := users.Permissions{
		Api: true, Share: true, Browse: true, Preview: true, Download: true,
		Create: true, Modify: true, Delete: true,
	}
	allCapabilities := managementShareCapabilities(true, true, true, true, true, true, true, true, true)
	readOnlyCapabilities := managementShareCapabilities(true, false, false, false, false, false, false, false, false)

	t.Run("create get list post update and patch use one safe DTO", func(t *testing.T) {
		owner := h.newOwner(t, "management-share-contract-owner", fullPermissions)
		password := "management-share-password-secret"
		body := dbshare.CreateBody{
			CommonShare: managementShareAllCapabilities("source1", "/public"),
			Password:    password,
		}
		createPayload, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		createResponse := callManagementShareHandler(t, sharePostHandler, http.MethodPost,
			"https://manage.example/api/share", createPayload, owner)
		created := decodeManagementShareObject(t, createResponse.Body.Bytes())
		hash := requireManagementShareIdentity(t, created)
		stored, err := store.Share.GetByHash(hash)
		if err != nil {
			t.Fatalf("load created share: %v", err)
		}
		assertManagementShareContract(t, "create", created, allCapabilities, allCapabilities,
			createResponse.Body.Bytes(), sourcePath, password, stored.PasswordHash, stored.Token)

		getResponse := callManagementShareHandler(t, shareGetHandler, http.MethodGet,
			"https://manage.example/api/share?"+url.Values{
				"path":   {"/public"},
				"source": {"source1"},
			}.Encode(), nil, owner)
		got := findManagementShareByHash(t, getResponse.Body.Bytes(), hash)
		assertManagementShareContract(t, "get", got, allCapabilities, allCapabilities,
			getResponse.Body.Bytes(), sourcePath, password, stored.PasswordHash, stored.Token)

		listResponse := callManagementShareHandler(t, shareListHandler, http.MethodGet,
			"https://manage.example/api/share/list", nil, owner)
		listed := findManagementShareByHash(t, listResponse.Body.Bytes(), hash)
		assertManagementShareContract(t, "list", listed, allCapabilities, allCapabilities,
			listResponse.Body.Bytes(), sourcePath, password, stored.PasswordHash, stored.Token)

		updateBody := dbshare.CreateBody{
			Hash:        hash,
			CommonShare: managementShareAllCapabilities("ignored-source", "/ignored-path"),
		}
		updatePayload, err := json.Marshal(updateBody)
		if err != nil {
			t.Fatal(err)
		}
		updateResponse := callManagementShareHandler(t, sharePostHandler, http.MethodPost,
			"https://manage.example/api/share", updatePayload, owner)
		updated := decodeManagementShareObject(t, updateResponse.Body.Bytes())
		assertManagementShareContract(t, "post update", updated, allCapabilities, allCapabilities,
			updateResponse.Body.Bytes(), sourcePath, password, stored.PasswordHash, stored.Token)

		newPath := filepath.Join(sourcePath, "public", "management-renamed")
		if err := os.MkdirAll(newPath, 0o755); err != nil {
			t.Fatalf("create patch target: %v", err)
		}
		patchPayload, err := json.Marshal(map[string]string{
			"hash": hash,
			"path": "/public/management-renamed",
		})
		if err != nil {
			t.Fatal(err)
		}
		patchResponse := callManagementShareHandler(t, sharePatchHandler, http.MethodPatch,
			"https://manage.example/api/share", patchPayload, owner)
		patched := decodeManagementShareObject(t, patchResponse.Body.Bytes())
		assertManagementShareContract(t, "patch update", patched, allCapabilities, allCapabilities,
			patchResponse.Body.Bytes(), sourcePath, password, stored.PasswordHash, stored.Token)
	})

	t.Run("current owner permissions only reduce effective capabilities", func(t *testing.T) {
		owner := h.newOwner(t, "management-share-revoked-owner", fullPermissions)
		link := h.saveShare(t, owner, "management-owner-revoked", "/public", func(common *dbshare.CommonShare) {
			*common = managementShareAllCapabilities(sourcePath, "/public")
		})
		owner.Permissions = users.Permissions{Api: true, Share: true, Browse: true}
		h.updateOwnerPermissions(t, owner)

		response := callManagementShareHandler(t, shareListHandler, http.MethodGet,
			"https://manage.example/api/share/list", nil, owner)
		payload := findManagementShareByHash(t, response.Body.Bytes(), link.Hash)
		assertManagementShareContract(t, "owner permission decline", payload, allCapabilities,
			readOnlyCapabilities, response.Body.Bytes(), sourcePath)
	})

	t.Run("administrator owner does not gain ungranted capabilities", func(t *testing.T) {
		owner := h.newOwner(t, "management-share-admin-owner", users.Permissions{
			Api: true, Admin: true, Share: true, Browse: true,
		})
		link := h.saveShare(t, owner, "management-admin-not-expanded", "/public", func(common *dbshare.CommonShare) {
			*common = managementShareAllCapabilities(sourcePath, "/public")
		})
		link.CreatorCapabilities = dbshare.CapabilitiesFromPermissions(fullPermissions)
		if err := store.Share.Save(link); err != nil {
			t.Fatalf("save admin capability fixture: %v", err)
		}

		response := callManagementShareHandler(t, shareListHandler, http.MethodGet,
			"https://manage.example/api/share/list", nil, owner)
		payload := findManagementShareByHash(t, response.Body.Bytes(), link.Hash)
		assertManagementShareContract(t, "administrator owner", payload, allCapabilities,
			readOnlyCapabilities, response.Body.Bytes(), sourcePath)
	})

	t.Run("creator snapshot remains an effective capability ceiling", func(t *testing.T) {
		owner := h.newOwner(t, "management-share-snapshot-owner", fullPermissions)
		link := h.saveShare(t, owner, "management-creator-snapshot", "/public", func(common *dbshare.CommonShare) {
			*common = managementShareAllCapabilities(sourcePath, "/public")
		})
		link.CreatorCapabilities = dbshare.CapabilitySnapshot{Share: true, Browse: true}
		if err := store.Share.Save(link); err != nil {
			t.Fatalf("save creator snapshot fixture: %v", err)
		}

		response := callManagementShareHandler(t, shareListHandler, http.MethodGet,
			"https://manage.example/api/share/list", nil, owner)
		payload := findManagementShareByHash(t, response.Body.Bytes(), link.Hash)
		assertManagementShareContract(t, "creator snapshot", payload, allCapabilities,
			readOnlyCapabilities, response.Body.Bytes(), sourcePath)
	})

	t.Run("file roots do not advertise directory write operations", func(t *testing.T) {
		owner := h.newOwner(t, "management-share-root-type-owner", fullPermissions)
		directory := filepath.Join(sourcePath, "public", "management-directory")
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatalf("create directory share root: %v", err)
		}
		directoryLink := h.saveShare(t, owner, "management-directory-root", "/public/management-directory", func(common *dbshare.CommonShare) {
			*common = managementShareAllCapabilities(sourcePath, "/public/management-directory")
		})
		fileLink := h.saveShare(t, owner, "management-file-root", "/public/secret.txt", func(common *dbshare.CommonShare) {
			*common = managementShareAllCapabilities(sourcePath, "/public/secret.txt")
		})

		response := callManagementShareHandler(t, shareListHandler, http.MethodGet,
			"https://manage.example/api/share/list", nil, owner)
		directoryPayload := findManagementShareByHash(t, response.Body.Bytes(), directoryLink.Hash)
		assertManagementShareContract(t, "directory root", directoryPayload, allCapabilities,
			allCapabilities, response.Body.Bytes(), sourcePath)
		filePayload := findManagementShareByHash(t, response.Body.Bytes(), fileLink.Hash)
		fileEffective := managementShareCapabilities(true, true, true, true, true, false, false, false, false)
		assertManagementShareContract(t, "file root", filePayload, allCapabilities,
			fileEffective, response.Body.Bytes(), sourcePath)
	})

	t.Run("management authorization is independent from public audience", func(t *testing.T) {
		owner := h.newOwner(t, "management-share-audience-owner", fullPermissions)
		link := h.saveShare(t, owner, "management-public-audience-independent", "/public", func(common *dbshare.CommonShare) {
			*common = managementShareAllCapabilities(sourcePath, "/public")
			common.DisableAnonymous = true
			common.AllowedUsernames = []string{"different-public-user"}
		})
		router := managementShareTestRouter()
		ownerToken := issueShareSecurityToken(t, owner, "management-share-owner-token", fullPermissions)
		ownerRequest := httptest.NewRequest(http.MethodGet, "/api/share/list", nil)
		ownerRequest.Header.Set("Authorization", "Bearer "+ownerToken)
		ownerResponse := httptest.NewRecorder()
		router.ServeHTTP(ownerResponse, ownerRequest)
		if ownerResponse.Code != http.StatusOK {
			t.Fatalf("owner management list: status=%d body=%s", ownerResponse.Code, ownerResponse.Body.String())
		}
		managed := findManagementShareByHash(t, ownerResponse.Body.Bytes(), link.Hash)
		assertManagementShareContract(t, "public audience independent", managed, allCapabilities,
			allCapabilities, ownerResponse.Body.Bytes(), sourcePath)

		limitedToken := issueShareSecurityToken(t, owner, "management-share-no-share-token", users.Permissions{Api: true})
		limitedRequest := httptest.NewRequest(http.MethodGet, "/api/share/list", nil)
		limitedRequest.Header.Set("Authorization", "Bearer "+limitedToken)
		limitedResponse := httptest.NewRecorder()
		router.ServeHTTP(limitedResponse, limitedRequest)
		if limitedResponse.Code != http.StatusForbidden {
			t.Errorf("token without Share permission: status=%d, want %d; body=%s",
				limitedResponse.Code, http.StatusForbidden, limitedResponse.Body.String())
		}
		if strings.Contains(limitedResponse.Body.String(), link.Hash) {
			t.Errorf("token without Share permission enumerated hash %q", link.Hash)
		}

		publicAudience := h.newOwner(t, "different-public-user", users.Permissions{Api: true, Browse: true})
		publicAudienceToken := issueShareSecurityToken(t, publicAudience, "management-share-public-audience-token", publicAudience.Permissions)
		publicAudienceRequest := httptest.NewRequest(http.MethodGet, "/api/share/list", nil)
		publicAudienceRequest.Header.Set("Authorization", "Bearer "+publicAudienceToken)
		publicAudienceResponse := httptest.NewRecorder()
		router.ServeHTTP(publicAudienceResponse, publicAudienceRequest)
		if strings.Contains(publicAudienceResponse.Body.String(), link.Hash) {
			t.Errorf("public Share audience enumerated management hash %q", link.Hash)
		}

		nonOwner := h.newOwner(t, "management-share-non-owner", fullPermissions)
		nonOwnerToken := issueShareSecurityToken(t, nonOwner, "management-share-non-owner-token", fullPermissions)
		nonOwnerRequest := httptest.NewRequest(http.MethodGet, "/api/share/list", nil)
		nonOwnerRequest.Header.Set("Authorization", "Bearer "+nonOwnerToken)
		nonOwnerResponse := httptest.NewRecorder()
		router.ServeHTTP(nonOwnerResponse, nonOwnerRequest)
		if nonOwnerResponse.Code != http.StatusOK {
			t.Fatalf("non-owner management list: status=%d body=%s", nonOwnerResponse.Code, nonOwnerResponse.Body.String())
		}
		if strings.Contains(nonOwnerResponse.Body.String(), link.Hash) {
			t.Errorf("non-owner with Share permission enumerated management hash %q", link.Hash)
		}

		anonymousRequest := httptest.NewRequest(http.MethodGet,
			"/api/share/list?"+url.Values{"hash": {link.Hash}}.Encode(), nil)
		anonymousResponse := httptest.NewRecorder()
		router.ServeHTTP(anonymousResponse, anonymousRequest)
		if anonymousResponse.Code == http.StatusOK {
			t.Errorf("anonymous management list unexpectedly succeeded: %s", anonymousResponse.Body.String())
		}
		if strings.Contains(anonymousResponse.Body.String(), link.Hash) {
			t.Errorf("anonymous management request enumerated hash %q", link.Hash)
		}
	})
}

func managementShareAllCapabilities(source, path string) dbshare.CommonShare {
	return dbshare.CommonShare{
		Source:            source,
		Path:              path,
		ShareType:         "normal",
		AllowCreate:       true,
		AllowModify:       true,
		AllowDelete:       true,
		AllowReplacements: true,
	}
}

func managementShareCapabilities(browse, preview, download, thumbnail, viewer, create, modify, deleteAllowed, replace bool) map[string]bool {
	return map[string]bool{
		"browse":    browse,
		"preview":   preview,
		"download":  download,
		"thumbnail": thumbnail,
		"viewer":    viewer,
		"create":    create,
		"modify":    modify,
		"delete":    deleteAllowed,
		"replace":   replace,
	}
}

func callManagementShareHandler(t *testing.T, handler handleFunc, method, target string, payload []byte, user *users.User) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, target, bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	status, err := handler(response, request, &requestContext{user: user})
	if err != nil || status != http.StatusOK {
		t.Fatalf("%s %s: status=%d err=%v body=%s", method, target, status, err, response.Body.String())
	}
	return response
}

func decodeManagementShareObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode management share object: %v; body=%s", err, raw)
	}
	return payload
}

func findManagementShareByHash(t *testing.T, raw []byte, hash string) map[string]any {
	t.Helper()
	var payloads []map[string]any
	if err := json.Unmarshal(raw, &payloads); err != nil {
		t.Fatalf("decode management share list: %v; body=%s", err, raw)
	}
	for _, payload := range payloads {
		if payloadHash, _ := payload["hash"].(string); payloadHash == hash {
			return payload
		}
	}
	t.Fatalf("management share %q not found in response: %s", hash, raw)
	return nil
}

func requireManagementShareIdentity(t *testing.T, payload map[string]any) string {
	t.Helper()
	hash, _ := payload["hash"].(string)
	if hash == "" {
		t.Fatalf("management share response has no hash: %#v", payload)
	}
	shareURL, _ := payload["shareURL"].(string)
	if shareURL == "" || !strings.Contains(shareURL, hash) {
		t.Errorf("management share response has invalid shareURL %q for hash %q", shareURL, hash)
	}
	return hash
}

func assertManagementShareContract(t *testing.T, scenario string, payload map[string]any, configured, effective map[string]bool, raw []byte, sourcePath string, secrets ...string) {
	t.Helper()
	requireManagementShareIdentity(t, payload)
	assertManagementShareCapabilities(t, scenario+" configuredCapabilities", payload["configuredCapabilities"], configured)
	assertManagementShareCapabilities(t, scenario+" effectiveCapabilities", payload["effectiveCapabilities"], effective)
	assertManagementShareSafeJSON(t, scenario, payload, raw, sourcePath, secrets...)
}

func assertManagementShareCapabilities(t *testing.T, scenario string, raw any, want map[string]bool) {
	t.Helper()
	capabilities, ok := raw.(map[string]any)
	if !ok {
		t.Errorf("%s is not an object: %#v", scenario, raw)
		return
	}
	if len(capabilities) != len(managementShareCapabilityNames) {
		t.Errorf("%s has %d fields, want exactly %d: %#v",
			scenario, len(capabilities), len(managementShareCapabilityNames), capabilities)
	}
	for _, name := range managementShareCapabilityNames {
		value, exists := capabilities[name]
		if !exists {
			t.Errorf("%s omits false-capable field %q", scenario, name)
			continue
		}
		got, ok := value.(bool)
		if !ok {
			t.Errorf("%s field %q is %T, want bool", scenario, name, value)
			continue
		}
		if got != want[name] {
			t.Errorf("%s field %q: got %t, want %t", scenario, name, got, want[name])
		}
	}
}

func assertManagementShareSafeJSON(t *testing.T, scenario string, payload map[string]any, raw []byte, sourcePath string, secrets ...string) {
	t.Helper()
	forbiddenKeys := map[string]struct{}{
		"passwordhash":  {},
		"password":      {},
		"token":         {},
		"accesstoken":   {},
		"cookie":        {},
		"authorization": {},
		"secret":        {},
		"createdat":     {},
	}
	var inspect func(map[string]any)
	inspect = func(object map[string]any) {
		for key, value := range object {
			normalized := strings.ToLower(strings.ReplaceAll(key, "_", ""))
			if _, forbidden := forbiddenKeys[normalized]; forbidden {
				t.Errorf("%s exposes forbidden JSON field %q", scenario, key)
			}
			switch typed := value.(type) {
			case map[string]any:
				inspect(typed)
			case []any:
				for _, element := range typed {
					if nested, ok := element.(map[string]any); ok {
						inspect(nested)
					}
				}
			case string:
				if strings.HasSuffix(strings.ToLower(key), "url") {
					parsed, err := url.Parse(typed)
					if err != nil {
						t.Errorf("%s has invalid %s %q: %v", scenario, key, typed, err)
						continue
					}
					for _, queryKey := range []string{"token", "password", "password_hash", "authorization", "cookie"} {
						if parsed.Query().Get(queryKey) != "" {
							t.Errorf("%s %s contains forbidden query parameter %q", scenario, key, queryKey)
						}
					}
				}
			}
		}
	}
	inspect(payload)
	text := string(raw)
	if sourcePath != "" && strings.Contains(text, sourcePath) {
		t.Errorf("%s exposes host source path %q", scenario, sourcePath)
	}
	for _, secret := range secrets {
		if secret != "" && strings.Contains(text, secret) {
			t.Errorf("%s exposes secret value %q", scenario, secret)
		}
	}
}

func managementShareTestRouter() http.Handler {
	api := http.NewServeMux()
	api.HandleFunc("GET /share/list", withPermShare(shareListHandler))
	api.HandleFunc("GET /share", withPermShare(shareGetHandler))
	api.HandleFunc("POST /share", withPermShare(sharePostHandler))
	api.HandleFunc("PATCH /share", withPermShare(sharePatchHandler))
	router := http.NewServeMux()
	router.Handle("/api/", http.StripPrefix("/api", api))
	return router
}
