package http

// Product materials are an opt-in client workflow over the existing scoped file
// service. Nothing here accepts host paths, remote URLs, executable commands or
// credentials. Publication only creates new immutable version files.
import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/files"
	commonerrors "github.com/gtsteffaniak/filebrowser/backend/common/errors"
	auditdb "github.com/gtsteffaniak/filebrowser/backend/database/audit"
)

const (
	productArchiveLimit  int64 = 128 << 20
	productExpandedLimit int64 = 512 << 20
	productMemberLimit   int64 = 32 << 20
	productMemberCount         = 2000
	productManifestName        = "product-materials.json"
)

var productLocks sync.Map

type productMember struct {
	Path       string `json:"path"`
	Size       int64  `json:"size_bytes"`
	SHA256     string `json:"sha256"`
	Category   string `json:"category,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
	StoredPath string `json:"stored_path,omitempty"`
}
type productRequest struct {
	Operation       string          `json:"operation,omitempty"`
	OperationID     string          `json:"operation_id,omitempty"`
	ExpectedSHA256  string          `json:"expected_sha256,omitempty"`
	ReplacementPath string          `json:"replacement_path,omitempty"`
	RecoveryRoot    string          `json:"recovery_root,omitempty"`
	RecoveryPath    string          `json:"recovery_path,omitempty"`
	Action          string          `json:"action"`
	Source          string          `json:"source"`
	Path            string          `json:"path"`
	SHA256          string          `json:"sha256,omitempty"`
	Destination     string          `json:"destination,omitempty"`
	Brand           string          `json:"brand,omitempty"`
	Product         string          `json:"product,omitempty"`
	Specification   string          `json:"specification,omitempty"`
	Version         string          `json:"version,omitempty"`
	Members         []productMember `json:"members,omitempty"`
	Categories      []string        `json:"categories,omitempty"`
	Name            string          `json:"name,omitempty"`
	Member          string          `json:"member,omitempty"`
}
type productManifest struct {
	Schema        string          `json:"schema"`
	State         string          `json:"state"`
	Source        string          `json:"source"`
	Path          string          `json:"path"`
	Brand         string          `json:"brand"`
	Product       string          `json:"product"`
	Specification string          `json:"specification"`
	Version       string          `json:"version"`
	Original      productMember   `json:"original"`
	Members       []productMember `json:"manifest"`
}

func productLabel(value string) bool {
	if value == "" || value == "." || value == ".." || len(value) > 180 || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || strings.ContainsRune("/\\:\x00<>\"|?*", r) {
			return false
		}
	}
	base := strings.ToUpper(strings.SplitN(value, ".", 2)[0])
	if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" {
		return false
	}
	if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9' {
		return false
	}
	return !strings.HasSuffix(value, ".")
}
func productCategory(value string) bool {
	return value == "main" || value == "detail" || value == "other" || value == "pending"
}

func productMaterialsHandler(w http.ResponseWriter, r *http.Request, d *requestContext) (int, error) {
	if err := r.Context().Err(); err != nil {
		return http.StatusRequestTimeout, err
	}
	if d.share != nil {
		return http.StatusForbidden, commonerrors.ErrAccessDenied
	}
	user, err := currentAuthenticatedArchiveUser(d)
	if err != nil {
		return http.StatusForbidden, err
	}
	enabled := false
	for _, username := range config.Server.ProductMaterialsUsers {
		if username == user.Username {
			enabled = true
			break
		}
	}
	if !enabled {
		return http.StatusForbidden, commonerrors.ErrAccessDenied
	}
	var req productRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, 2<<20))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&req) != nil || req.Source == "" || req.Path == "" {
		return http.StatusBadRequest, fmt.Errorf("invalid product request")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return http.StatusBadRequest, fmt.Errorf("invalid trailing JSON")
	}
	if req.Action != "inspect" && req.Action != "preview" && req.Action != "import" && req.Action != "export" && req.Action != "organize" {
		return http.StatusBadRequest, fmt.Errorf("unsupported product action")
	}
	if req.Action == "import" || req.Action == "export" {
		if !user.Permissions.Create {
			return http.StatusForbidden, commonerrors.ErrAccessDenied
		}
	}
	if req.Action == "organize" {
		return productOrganize(w, r, d, req)
	}
	if req.Action == "export" {
		return productExport(w, r, d, req)
	}
	target, err := resolveAuthenticatedReadTarget(user, req.Source, req.Path)
	if err != nil {
		return productErrorStatus(err), err
	}
	if target.Info == nil || !target.Info.Mode().IsRegular() || target.Info.Size() > productArchiveLimit || !strings.HasSuffix(strings.ToLower(req.Path), ".zip") {
		return http.StatusBadRequest, fmt.Errorf("bounded ZIP required")
	}
	if authenticatedReadPathContainsSymlink(target.SourcePath, target.LogicalPath) {
		return http.StatusForbidden, commonerrors.ErrAccessDenied
	}
	if err = setCoreFileAuditReadTarget(r, target, nil); err != nil {
		return http.StatusServiceUnavailable, err
	}
	snapshot, _, cleanup, err := snapshotAuthenticatedReadTarget(target)
	if err != nil {
		return productErrorStatus(err), err
	}
	defer cleanup()
	archiveHash, size, err := productFileHash(snapshot, productArchiveLimit)
	if err != nil {
		return http.StatusBadRequest, err
	}
	members, err := inspectProductZipContext(r.Context(), snapshot)
	if err != nil {
		return http.StatusBadRequest, err
	}
	if req.Action == "inspect" || req.Action == "preview" {
		if recorder := AuditRecorderFromRequest(r); recorder != nil {
			if err = recorder.SetAction(auditdb.ActionFileBrowse); err != nil {
				return http.StatusServiceUnavailable, err
			}
		}
	}
	if req.Action == "inspect" {
		return renderJSON(w, r, map[string]any{"source": req.Source, "path": req.Path, "sha256": archiveHash, "size_bytes": size, "manifest": members, "untrusted_content": true}, http.StatusOK)
	}
	if req.SHA256 != archiveHash {
		return http.StatusConflict, fmt.Errorf("archive changed since inspection")
	}
	if req.Action == "preview" {
		for _, member := range members {
			if member.Path == req.Member {
				if member.Size > 12<<20 {
					return http.StatusRequestEntityTooLarge, fmt.Errorf("preview too large")
				}
				z, e := zip.OpenReader(snapshot)
				if e != nil {
					return http.StatusBadRequest, e
				}
				defer z.Close()
				for _, f := range z.File {
					if f.Name == member.Path {
						src, e := f.Open()
						if e != nil {
							return http.StatusBadRequest, e
						}
						defer src.Close()
						data, e := io.ReadAll(io.LimitReader(src, (12<<20)+1))
						if e != nil {
							return http.StatusBadRequest, e
						}
						mime := http.DetectContentType(data)
						if mime != "image/jpeg" && mime != "image/png" {
							return http.StatusUnsupportedMediaType, fmt.Errorf("preview supports PNG/JPEG")
						}
						return renderJSON(w, r, map[string]any{"source": req.Source, "path": req.Path, "member": member.Path, "mime_type": mime, "data_base64": base64.StdEncoding.EncodeToString(data), "sha256": member.SHA256, "untrusted_content": true}, http.StatusOK)
					}
				}
			}
		}
		return http.StatusNotFound, fmt.Errorf("member not found")
	}
	if !productLabel(req.Brand) || !productLabel(req.Product) || !productLabel(req.Specification) || !productLabel(req.Version) {
		return http.StatusBadRequest, fmt.Errorf("explicit brand product specification version required; clarify ambiguity")
	}
	destination := path.Join(req.Destination, req.Brand, req.Product, req.Specification, req.Version)
	muAny, _ := productLocks.LoadOrStore(req.Source+"\x00"+destination, &sync.Mutex{})
	mu, validLock := muAny.(*sync.Mutex)
	if !validLock {
		return http.StatusInternalServerError, fmt.Errorf("product lock unavailable")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(req.Members) != len(members) {
		return http.StatusBadRequest, fmt.Errorf("classification must account for every regular member")
	}
	byPath := map[string]productMember{}
	for _, m := range req.Members {
		if _, exists := byPath[m.Path]; exists || !productCategory(m.Category) || strings.TrimSpace(m.Evidence) == "" || len(m.Evidence) > 2000 {
			return http.StatusBadRequest, fmt.Errorf("invalid or duplicate classification")
		}
		byPath[m.Path] = m
	}
	for i, m := range members {
		selected, exists := byPath[m.Path]
		if !exists || selected.SHA256 != m.SHA256 || selected.Size != m.Size {
			return http.StatusConflict, fmt.Errorf("member manifest mismatch")
		}
		members[i].Category = selected.Category
		members[i].Evidence = selected.Evidence
		members[i].StoredPath = path.Join(destination, selected.Category, m.Path)
	}
	// Reserve audit before creating anything. Partial files remain distinguishable
	// because the completion manifest is exclusively published last.
	if err = prepareResourceWriteAudit(r, auditdb.ActionArchiveExtract, req.Source, destination, destination, "", "", "", resourceWriteAuditMetadata(auditdb.MethodPOST, int64(len(members)+2))); err != nil {
		return http.StatusServiceUnavailable, err
	}
	if err = reserveResourceWriteAudit(r); err != nil {
		return http.StatusServiceUnavailable, err
	}
	if err = productEnsureDirs(d, req.Source, req.Destination); err != nil {
		return productErrorStatus(err), err
	}
	manifest := productManifest{Schema: "cf-product-materials/v1", State: "complete", Source: req.Source, Path: destination, Brand: req.Brand, Product: req.Product, Specification: req.Specification, Version: req.Version, Original: productMember{Path: req.Path, Size: size, SHA256: archiveHash, StoredPath: path.Join(destination, "original", path.Base(req.Path))}, Members: members}
	encoded, _ := json.Marshal(manifest)
	pending := manifest
	pending.State = "pending"
	pendingBytes, _ := json.Marshal(pending)
	pendingPath := path.Join(destination, "product-materials.pending.json")
	currentUser, authErr := currentAuthenticatedArchiveUser(d)
	if authErr != nil {
		return http.StatusForbidden, authErr
	}
	existingVersion, versionErr := resolveAuthenticatedBrowseTarget(currentUser, req.Source, destination)
	if versionErr == nil && existingVersion.Info != nil {
		known, knownErr := productRead(d, req.Source, pendingPath, 2<<20)
		if knownErr != nil || string(known) != string(pendingBytes) {
			return http.StatusConflict, fmt.Errorf("existing version has no matching import intent")
		}
	} else if versionErr != nil && !os.IsNotExist(versionErr) && !errors.Is(versionErr, commonerrors.ErrNotExist) {
		return productErrorStatus(versionErr), versionErr
	}
	if versionErr != nil {
		// The final version directory is a reservation, never a merge target.
		if err = productEnsureDirs(d, req.Source, path.Dir(destination)); err != nil {
			return productErrorStatus(err), err
		}
		currentUser, err = currentAuthenticatedArchiveUser(d)
		if err != nil {
			return http.StatusForbidden, err
		}
		reserved, reserveErr := resolveAuthenticatedWriteTarget(currentUser, req.Source, destination)
		if reserveErr != nil {
			return productErrorStatus(reserveErr), reserveErr
		}
		if !currentUser.Permissions.Create || authenticatedReadPathContainsSymlink(reserved.SourcePath, path.Dir(reserved.LogicalPath)) {
			return http.StatusForbidden, commonerrors.ErrAccessDenied
		}
		if err = os.Mkdir(reserved.RealPath, 0755); err != nil {
			if os.IsExist(err) {
				return http.StatusConflict, fmt.Errorf("version appeared concurrently; inspect before retry")
			}
			return productErrorStatus(err), err
		}
		if err = files.RefreshIndex(req.Source, reserved.CanonicalPath, true, false); err != nil {
			return http.StatusInternalServerError, err
		}
	}
	if err = productPublishBytes(d, req.Source, pendingPath, pendingBytes); err != nil {
		return productErrorStatus(err), err
	}
	// An existing completion manifest must be byte-identical; no version takeover.
	if existing, e := productRead(d, req.Source, path.Join(destination, productManifestName), 2<<20); e == nil && string(existing) != string(encoded) {
		return http.StatusConflict, fmt.Errorf("version already belongs to a different manifest")
	}
	stage, err := os.MkdirTemp("", "filebrowser-product-*")
	if err != nil {
		return http.StatusInternalServerError, err
	}
	defer os.RemoveAll(stage)
	plan, err := scanZipExtractionPlan(snapshot, stage)
	if err != nil {
		return http.StatusBadRequest, err
	}
	if err = extractZipWithPlan(snapshot, stage, plan); err != nil {
		return http.StatusBadRequest, err
	}
	if err = productPublishLocal(d, req.Source, manifest.Original.StoredPath, snapshot, archiveHash); err != nil {
		return productErrorStatus(err), err
	}
	for _, m := range members {
		if err = r.Context().Err(); err != nil {
			return http.StatusRequestTimeout, err
		}
		if err = productPublishLocal(d, req.Source, m.StoredPath, filepath.Join(stage, filepath.FromSlash(m.Path)), m.SHA256); err != nil {
			return productErrorStatus(err), err
		}
	}
	// This resolver accepts a source index path, not a user-relative API path.
	current, e := resolveCurrentAuthenticatedArchiveTarget(d, req.Source, target.CanonicalPath)
	if e != nil || !sameAuthenticatedReadTarget(target, current) {
		return http.StatusConflict, fmt.Errorf("archive or permission changed before completion")
	}
	// Recheck all published bytes before declaring the version complete. An
	// employee may have edited a file while a long import was still running.
	for _, m := range append([]productMember{manifest.Original}, members...) {
		if err = r.Context().Err(); err != nil {
			return http.StatusRequestTimeout, err
		}
		user, authErr := currentAuthenticatedArchiveUser(d)
		if authErr != nil {
			return http.StatusForbidden, authErr
		}
		item, itemErr := resolveAuthenticatedReadTarget(user, req.Source, m.StoredPath)
		if itemErr != nil {
			return productErrorStatus(itemErr), itemErr
		}
		sum, sumErr := checksumAuthenticatedReadTarget(item, "sha256")
		if sumErr != nil || sum != m.SHA256 || item.Info.Size() != m.Size {
			return http.StatusConflict, fmt.Errorf("published member changed before completion")
		}
	}
	// The marker is a receipt, not an authority: exports re-authorize and hash all
	// listed source files, and resume validates every file before publishing it.
	if err = productPublishBytes(d, req.Source, path.Join(destination, productManifestName), encoded); err != nil {
		return productErrorStatus(err), err
	}
	return renderJSON(w, r, manifest, http.StatusOK)
}

func inspectProductZip(filename string) ([]productMember, error) {
	return inspectProductZipContext(context.Background(), filename)
}
func inspectProductZipContext(ctx context.Context, filename string) ([]productMember, error) {
	z, err := zip.OpenReader(filename)
	if err != nil {
		return nil, fmt.Errorf("invalid ZIP")
	}
	defer z.Close()
	if len(z.File) == 0 || len(z.File) > productMemberCount {
		return nil, fmt.Errorf("ZIP member count limit")
	}
	seen := map[string]bool{}
	result := []productMember{}
	var total int64
	for _, f := range z.File {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		relative, e := normalizeArchiveEntryName(f.Name)
		if e != nil || relative == "" || strings.Contains(f.Name, "\\") || strings.Contains(relative, ":") || strings.HasPrefix(f.Name, "/") {
			return nil, fmt.Errorf("unsafe ZIP path")
		}
		for _, c := range f.Name {
			if unicode.IsControl(c) {
				return nil, fmt.Errorf("unsafe ZIP character")
			}
		}
		key := strings.ToLower(strings.TrimSuffix(relative, "/"))
		if seen[key] {
			return nil, fmt.Errorf("duplicate ZIP path")
		}
		seen[key] = true
		mode := f.FileInfo().Mode()
		if f.Flags&1 != 0 {
			return nil, fmt.Errorf("encrypted ZIP unsupported")
		}
		if mode&fs.ModeSymlink != 0 || (!mode.IsRegular() && !mode.IsDir()) {
			return nil, fmt.Errorf("ZIP links and special files denied")
		}
		compressed := f.CompressedSize64
		if compressed == 0 {
			compressed = 1
		}
		if f.UncompressedSize64 > uint64(productMemberLimit) || f.UncompressedSize64 > uint64(productExpandedLimit-total) || compressed > uint64(productArchiveLimit) || f.UncompressedSize64 > compressed*200 {
			return nil, fmt.Errorf("ZIP expansion limit")
		}
		if mode.IsDir() {
			continue
		}
		total += int64(f.UncompressedSize64)
		src, e := f.Open()
		if e != nil {
			return nil, fmt.Errorf("invalid ZIP member")
		}
		h := sha256.New()
		n, e := io.Copy(h, io.LimitReader(src, productMemberLimit+1))
		ce := src.Close()
		if e != nil || ce != nil || n != int64(f.UncompressedSize64) {
			return nil, fmt.Errorf("ZIP member checksum or length mismatch")
		}
		result = append(result, productMember{Path: relative, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))})
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("ZIP contains no regular files")
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result, nil
}

func productFileHash(filename string, limit int64) (string, int64, error) {
	f, e := os.Open(filename)
	if e != nil {
		return "", 0, e
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, limit+1))
	if e != nil {
		return "", n, e
	}
	if n > limit {
		return "", n, fmt.Errorf("file size limit")
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
func productRead(d *requestContext, source, p string, limit int64) ([]byte, error) {
	u, e := currentAuthenticatedArchiveUser(d)
	if e != nil {
		return nil, e
	}
	t, e := resolveAuthenticatedReadTarget(u, source, p)
	if e != nil {
		return nil, e
	}
	if t.Info == nil || !t.Info.Mode().IsRegular() || t.Info.Size() > limit {
		return nil, fmt.Errorf("file size limit")
	}
	f, _, e := openAuthenticatedReadTarget(t)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit+1))
}
func productEnsureDirs(d *requestContext, source, p string) error {
	if p == "/" || p == "." || p == "" {
		return nil
	}
	u, e := currentAuthenticatedArchiveUser(d)
	if e != nil {
		return e
	}
	if !u.Permissions.Create {
		return commonerrors.ErrAccessDenied
	}
	t, e := resolveAuthenticatedBrowseTarget(u, source, p)
	if e == nil {
		if t.Info == nil || !t.Info.IsDir() || authenticatedReadPathContainsSymlink(t.SourcePath, t.LogicalPath) {
			return commonerrors.ErrAccessDenied
		}
		return nil
	}
	if !os.IsNotExist(e) && !errors.Is(e, commonerrors.ErrNotExist) {
		return e
	}
	if e = productEnsureDirs(d, source, path.Dir(p)); e != nil {
		return e
	}
	u, e = currentAuthenticatedArchiveUser(d)
	if e != nil {
		return e
	}
	t, e = resolveAuthenticatedWriteTarget(u, source, p)
	if e != nil {
		return e
	}
	if !u.Permissions.Create || authenticatedReadPathContainsSymlink(t.SourcePath, path.Dir(t.LogicalPath)) {
		return commonerrors.ErrAccessDenied
	}
	if e = os.Mkdir(t.RealPath, 0755); e != nil && !os.IsExist(e) {
		return e
	}
	return files.RefreshIndex(source, t.CanonicalPath, true, false)
}
func productPublishBytes(d *requestContext, source, p string, data []byte) error {
	f, e := os.CreateTemp("", "filebrowser-product-receipt-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	_, e = f.Write(data)
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	h := sha256.Sum256(data)
	return productPublishLocal(d, source, p, name, hex.EncodeToString(h[:]))
}
func productPublishLocal(d *requestContext, source, p, local, expected string) error {
	if e := productEnsureDirs(d, source, path.Dir(p)); e != nil {
		return e
	}
	u, e := currentAuthenticatedArchiveUser(d)
	if e != nil {
		return e
	}
	if !u.Permissions.Create {
		return commonerrors.ErrAccessDenied
	}
	target, e := resolveAuthenticatedWriteTarget(u, source, p)
	if e != nil {
		return e
	}
	if authenticatedReadPathContainsSymlink(target.SourcePath, path.Dir(target.LogicalPath)) {
		return commonerrors.ErrAccessDenied
	}
	if target.Info != nil {
		if !target.Info.Mode().IsRegular() {
			return errArchiveExtractionConflict
		}
		digest, checksumErr := checksumAuthenticatedReadTarget(target, "sha256")
		if checksumErr != nil {
			return checksumErr
		}
		if digest != expected {
			return errArchiveExtractionConflict
		}
		return nil
	}
	src, e := os.Open(local)
	if e != nil {
		return e
	}
	defer src.Close()
	tmp, e := os.CreateTemp(filepath.Dir(target.RealPath), ".filebrowser-product-write-*")
	if e != nil {
		return e
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	h := sha256.New()
	_, e = io.Copy(io.MultiWriter(tmp, h), io.LimitReader(src, productArchiveLimit+1))
	if e == nil && hex.EncodeToString(h.Sum(nil)) != expected {
		e = errArchiveExtractionConflict
	}
	if e == nil {
		e = tmp.Sync()
	}
	ce := tmp.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	u, e = currentAuthenticatedArchiveUser(d)
	if e != nil {
		return e
	}
	latest, e := resolveAuthenticatedWriteTarget(u, source, p)
	if e != nil {
		return e
	}
	if !u.Permissions.Create || !sameResourceAuditWriteTarget(target, latest) {
		return errArchiveExtractionConflict
	}
	// Link is an atomic no-replace publication, unlike Rename on POSIX. Unsupported
	// filesystems fail closed; no fallback may overwrite an employee's new file.
	if e = os.Chmod(tmpName, 0644); e != nil {
		return e
	}
	if e = os.Link(tmpName, target.RealPath); e != nil {
		return e
	}
	return files.RefreshIndex(source, target.CanonicalPath, false, false)
}

func productExport(w http.ResponseWriter, r *http.Request, d *requestContext, req productRequest) (int, error) {
	if !productLabel(req.Name) || !strings.HasSuffix(strings.ToLower(req.Name), ".zip") {
		return http.StatusBadRequest, fmt.Errorf("explicit ZIP name required")
	}
	data, e := productRead(d, req.Source, path.Join(req.Path, productManifestName), 2<<20)
	if e != nil {
		return productErrorStatus(e), e
	}
	var manifest productManifest
	if json.Unmarshal(data, &manifest) != nil || manifest.Schema != "cf-product-materials/v1" || manifest.State != "complete" || manifest.Path != path.Clean(req.Path) || manifest.Source != req.Source {
		return http.StatusConflict, fmt.Errorf("complete matching product manifest required")
	}
	if len(req.Categories) == 0 {
		return http.StatusBadRequest, fmt.Errorf("explicit categories required")
	}
	wanted := map[string]bool{}
	for _, c := range req.Categories {
		if !productCategory(c) {
			return http.StatusBadRequest, fmt.Errorf("invalid category")
		}
		wanted[c] = true
	}
	destination := path.Join(req.Destination, req.Name)
	if e = prepareResourceWriteAudit(r, auditdb.ActionArchiveCreate, req.Source, destination, destination, "", "", "", resourceWriteAuditMetadata(auditdb.MethodPOST, 1)); e != nil {
		return http.StatusServiceUnavailable, e
	}
	if e = reserveResourceWriteAudit(r); e != nil {
		return http.StatusServiceUnavailable, e
	}
	temp, e := os.CreateTemp("", "filebrowser-product-export-*.zip")
	if e != nil {
		return http.StatusInternalServerError, e
	}
	tmpName := temp.Name()
	defer os.Remove(tmpName)
	defer temp.Close()
	writer := zip.NewWriter(temp)
	defer writer.Close()
	selected := []productMember{}
	var total int64
	seen := map[string]bool{}
	for _, m := range manifest.Members {
		if err := r.Context().Err(); err != nil {
			return http.StatusRequestTimeout, err
		}
		if !wanted[m.Category] {
			continue
		}
		normalized, pathErr := normalizeArchiveEntryName(m.Path)
		if pathErr != nil || normalized != m.Path || !productCategory(m.Category) {
			return http.StatusConflict, fmt.Errorf("unsafe manifest member")
		}
		relative := path.Join(m.Category, m.Path)
		if m.StoredPath != path.Join(req.Path, relative) || seen[relative] || m.Size < 0 || m.Size > productMemberLimit || total+m.Size > productExpandedLimit || len(selected) >= productMemberCount {
			return http.StatusConflict, fmt.Errorf("invalid member manifest")
		}
		seen[relative] = true
		total += m.Size
		u, err := currentAuthenticatedArchiveUser(d)
		if err != nil {
			return http.StatusForbidden, err
		}
		target, err := resolveAuthenticatedReadTarget(u, req.Source, m.StoredPath)
		if err != nil {
			return productErrorStatus(err), err
		}
		if target.Info == nil || !target.Info.Mode().IsRegular() || target.Info.Size() != m.Size || authenticatedReadPathContainsSymlink(target.SourcePath, target.LogicalPath) {
			return http.StatusConflict, fmt.Errorf("selected member changed")
		}
		snapshot, _, cleanup, err := snapshotAuthenticatedReadTarget(target)
		if err != nil {
			return productErrorStatus(err), err
		}
		hash, _, err := productFileHash(snapshot, productMemberLimit)
		if err == nil && hash != m.SHA256 {
			err = errArchiveExtractionConflict
		}
		if err == nil {
			// Only the isolated snapshot metadata is normalized. Repeated export
			// of the same frozen members must produce the same ZIP bytes.
			fixedTime := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
			err = os.Chtimes(snapshot, fixedTime, fixedTime)
			if err == nil {
				err = addSingleFile(snapshot, relative, writer, nil)
			}
		}
		cleanup()
		if err != nil {
			return productErrorStatus(err), err
		}
		selected = append(selected, productMember{Path: relative, Size: m.Size, SHA256: m.SHA256})
	}
	closeErr := writer.Close()
	fileErr := temp.Close()
	if closeErr != nil || fileErr != nil || len(selected) == 0 {
		return http.StatusBadRequest, fmt.Errorf("empty or incomplete export")
	}
	hash, size, e := productFileHash(tmpName, productArchiveLimit)
	if e != nil {
		return http.StatusRequestEntityTooLarge, e
	}
	actual, e := inspectProductZip(tmpName)
	if e != nil {
		return http.StatusBadRequest, e
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].Path < selected[j].Path })
	a, _ := json.Marshal(actual)
	b, _ := json.Marshal(selected)
	if string(a) != string(b) {
		return http.StatusConflict, fmt.Errorf("generated ZIP member verification failed")
	}
	// Recheck every selected member after building; no silent omission or mixing of
	// an employee's concurrent replacement with the frozen version manifest.
	for _, m := range selected {
		if err := r.Context().Err(); err != nil {
			return http.StatusRequestTimeout, err
		}
		u, err := currentAuthenticatedArchiveUser(d)
		if err != nil {
			return http.StatusForbidden, err
		}
		t, err := resolveAuthenticatedReadTarget(u, req.Source, path.Join(req.Path, m.Path))
		if err != nil {
			return productErrorStatus(err), err
		}
		fresh, err := checksumAuthenticatedReadTarget(t, "sha256")
		if err != nil || fresh != m.SHA256 {
			return http.StatusConflict, fmt.Errorf("selected member changed during export")
		}
	}
	if e = productPublishLocal(d, req.Source, destination, tmpName, hash); e != nil {
		return productErrorStatus(e), e
	}
	return renderJSON(w, r, map[string]any{"source": req.Source, "path": destination, "name": req.Name, "mime_type": "application/zip", "size_bytes": size, "sha256": hash, "manifest": selected}, http.StatusOK)
}

func productErrorStatus(err error) int {
	if errors.Is(err, errArchiveExtractionConflict) || os.IsExist(err) {
		return http.StatusConflict
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return http.StatusRequestTimeout
	}
	return errToStatus(err)
}
