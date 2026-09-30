// FileBridge-Setup authenticates a fixed CI package, then calls the existing
// Windows transaction components. It has no downloader or file-service client.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// CI embeds the manifest itself, not a digest supplied by an editable neighbour.
// Initial executable trust comes from the fixed GitHub Actions artifact channel;
// CI also attests this executable. No self-signed/local trust is claimed.
var pinnedManifest string

type manifest struct {
	Schema    string            `json:"schema"`
	Source    string            `json:"source_commit"`
	Inventory string            `json:"inventory_sha256"`
	Files     map[string]string `json:"files"`
}

var errPackage = errors.New("CF_SETUP_PACKAGE_VERIFICATION_FAILED")
var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var hex40 = regexp.MustCompile(`^[0-9a-f]{40}$`)

func memberPath(root, name string) (string, error) {
	if name == "" || strings.ContainsAny(name, `\:`) || strings.HasPrefix(name, "/") {
		return "", errPackage
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." || strings.TrimRight(part, ". ") != part {
			return "", errPackage
		}
	}
	p := filepath.Join(root, filepath.FromSlash(name))
	for current := p; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || isReparse(info) {
			return "", errPackage
		}
		if current == root {
			break
		}
		if filepath.Dir(current) == current {
			return "", errPackage
		}
	}
	return p, nil
}

func verifyPackage(root string, data []byte) (manifest, error) {
	var m manifest
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF || m.Schema != "cf-filebridge-setup/v1" ||
		!hex40.MatchString(m.Source) || !hex64.MatchString(m.Inventory) || len(m.Files) == 0 || len(m.Files) > 64 {
		return m, errPackage
	}
	seen := map[string]bool{}
	for name, pin := range m.Files {
		key := strings.ToLower(name)
		if !hex64.MatchString(pin) || seen[key] {
			return m, errPackage
		}
		seen[key] = true
		p, err := memberPath(root, name)
		if err != nil {
			return m, err
		}
		f, err := os.Open(p)
		if err != nil {
			return m, errPackage
		}
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 512<<20 {
			_ = f.Close()
			return m, errPackage
		}
		h := sha256.New()
		_, err = io.Copy(h, f)
		_ = f.Close()
		if err != nil || hex.EncodeToString(h.Sum(nil)) != pin {
			return m, errPackage
		}
	}
	return m, nil
}

func run() error {
	data, err := base64.StdEncoding.DecodeString(pinnedManifest)
	if err != nil || len(data) == 0 || len(data) > 32768 {
		return errPackage
	}
	exe, err := os.Executable()
	if err != nil {
		return errPackage
	}
	root := filepath.Dir(exe)
	m, err := verifyPackage(root, data)
	if err != nil {
		return err
	}
	// Inspection is read-only and is used by packaging CI; installation still
	// requires the interactive confirmation in the verified PowerShell entry.
	if len(os.Args) == 2 && os.Args[1] == "--verify-package" {
		return nil
	}
	if len(os.Args) != 1 {
		return errors.New("CF_SETUP_ARGUMENTS_REFUSED")
	}
	return launch(root, m, data)
}

func main() {
	if err := run(); err != nil {
		showFailure(err)
		os.Exit(1)
	}
}
