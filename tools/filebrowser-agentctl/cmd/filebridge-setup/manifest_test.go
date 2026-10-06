package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinnedPackage(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Setup-FileBridge.ps1"), []byte("approved"), 0600); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte("approved"))
	m := manifest{Schema: "cf-filebridge-setup/v1", Source: strings.Repeat("a", 40), Inventory: strings.Repeat("b", 64), Files: map[string]string{"Setup-FileBridge.ps1": hex.EncodeToString(h[:])}}
	b, _ := json.Marshal(m)
	if _, err := verifyPackage(root, b); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "Setup-FileBridge.ps1"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyPackage(root, b); err == nil {
		t.Fatal("modified component accepted")
	}
	for _, name := range []string{"../escape", "C:/absolute", "/absolute", "a\\b", "a:stream", "a/../b", "a./b", "a /b"} {
		m.Files = map[string]string{name: hex.EncodeToString(h[:])}
		b, _ = json.Marshal(m)
		if _, err := verifyPackage(root, b); err == nil {
			t.Fatalf("unsafe member accepted: %s", name)
		}
	}
}

func TestManifestCannotSelfAuthorize(t *testing.T) {
	for _, data := range []string{`{}`, `{"schema":"wrong"}`, `{"schema":"cf-filebridge-setup/v1","unexpected":true}`} {
		if _, err := verifyPackage(t.TempDir(), []byte(data)); err == nil {
			t.Fatal("invalid manifest accepted")
		}
	}
}
