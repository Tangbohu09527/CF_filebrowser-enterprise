package inbound

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func privateStoreDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	ensureTestPrivateStore(t, dir)
	return dir
}

func TestStorePublishResolveAndTraversal(t *testing.T) {
	dir := privateStoreDir(t)
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p, err := s.Create()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Abort()
	if _, err = p.File.Write([]byte("verified bytes")); err != nil {
		t.Fatal(err)
	}
	name, err := p.Publish()
	if err != nil {
		t.Fatal(err)
	}
	if !internalName.MatchString(name) {
		t.Fatalf("uncontrolled name: %q", name)
	}
	f, err := s.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(f)
	f.Close()
	if err != nil || string(data) != "verified bytes" {
		t.Fatalf("read result: %q %v", data, err)
	}
	for _, bad := range []string{"../" + name, `..\` + name, filepath.Join(dir, name), name + ":stream", name + ".", "work-00000000000000000000000000000000"} {
		if file, err := s.Open(bad); err == nil {
			file.Close()
			t.Errorf("accepted %q", bad)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != name {
		t.Fatalf("publication left staging: %v %v", entries, err)
	}
}

func TestStoreAbortDoesNotDeliverPartialOrDeleteUnknown(t *testing.T) {
	dir := privateStoreDir(t)
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	unknown := filepath.Join(dir, "operator-file")
	if err := os.WriteFile(unknown, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := s.Create()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = p.File.Write([]byte("partial"))
	if err = p.Abort(); err != nil {
		t.Fatal(err)
	}
	if err = p.Abort(); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Publish(); err == nil {
		t.Fatal("published aborted file")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "operator-file" {
		t.Fatalf("unexpected cleanup: %v %v", entries, err)
	}
	data, err := os.ReadFile(unknown)
	if err != nil || string(data) != "keep" {
		t.Fatal("unknown file changed")
	}
}

func TestStoreAbortRejectsReplacedObject(t *testing.T) {
	dir := privateStoreDir(t)
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p, err := s.Create()
	if err != nil {
		t.Fatal(err)
	}
	if err = p.File.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, p.name)
	if err = os.Rename(path, filepath.Join(dir, "retained-original")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte("unrelated replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	// Windows refuses the replaced identity; Linux has anonymous staging and
	// never removes any path during Abort. Both must preserve unknown bytes.
	_ = p.Abort()
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "unrelated replacement" {
		t.Fatal("deleted or changed unknown replacement")
	}
}

func TestStoreNoOverwriteAndClose(t *testing.T) {
	dir := privateStoreDir(t)
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Create()
	if err != nil {
		t.Fatal(err)
	}
	name := "work-00000000000000000000000000000001"
	if err = os.WriteFile(filepath.Join(dir, name), []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.backend.publish(p.File, p.name, name, p.identity); err == nil {
		t.Fatal("publication replaced existing file")
	}
	data, _ := os.ReadFile(filepath.Join(dir, name))
	if string(data) != "existing" {
		t.Fatal("existing file was changed")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Create(); err == nil {
		t.Fatal("closed store accepted writer")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStoreRejectsRelativeMissingAndRoot(t *testing.T) {
	dir := privateStoreDir(t)
	for _, bad := range []string{".", "relative", filepath.Join(dir, "missing"), filepath.VolumeName(dir) + string(os.PathSeparator)} {
		if store, err := OpenStore(bad); err == nil {
			store.Close()
			t.Errorf("accepted unsafe directory %q", bad)
		}
	}
}

func TestStoreCancelledPublishAndReplacedWorkCopy(t *testing.T) {
	dir := privateStoreDir(t)
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p, err := s.Create()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = p.File.WriteString("unfinished")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if name, err := p.PublishContext(ctx); err == nil || name != "" {
		t.Fatal("cancelled dispatch published a handle")
	}
	if err = p.Abort(); err != nil {
		t.Fatal(err)
	}
	p, err = s.Create()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = p.File.WriteString("verified")
	name, err := p.Publish()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err = os.Rename(path, filepath.Join(dir, "retained-work-copy")); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if f, err := s.Open(name); err == nil {
		f.Close()
		t.Fatal("resolved replaced file identity")
	}
}
