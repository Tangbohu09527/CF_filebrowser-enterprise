//go:build windows

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"syscall"
	"unsafe"
)

func isReparse(info os.FileInfo) bool {
	data, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return !ok || data.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

func newPrivateCache(parent string) (string, error) {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return "", errPackage
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", errPackage
	}
	sid, err := user.User.Sid.String()
	if err != nil {
		return "", errPackage
	}
	sddl, _ := syscall.UTF16PtrFromString("O:" + sid + "D:P(A;OICI;FA;;;" + sid + ")(A;OICI;FA;;;SY)")
	var descriptor uintptr
	convert := syscall.NewLazyDLL("advapi32.dll").NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	ok, _, _ := convert.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), 0)
	if ok == 0 {
		return "", errPackage
	}
	defer syscall.LocalFree(syscall.Handle(descriptor))
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return "", errPackage
	}
	root := filepath.Join(parent, "CF-FileBridge-setup-"+hex.EncodeToString(nonce[:]))
	path, _ := syscall.UTF16PtrFromString(root)
	sa := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: descriptor}
	if syscall.CreateDirectory(path, &sa) != nil {
		return "", errPackage
	}
	return root, nil
}

func lockParents(path string) ([]syscall.Handle, error) {
	var locks []syscall.Handle
	for current := path; ; current = filepath.Dir(current) {
		p, err := syscall.UTF16PtrFromString(current)
		if err != nil {
			return locks, errPackage
		}
		// Metadata-only handles do not enforce delete sharing on directories.
		h, err := syscall.CreateFile(p, 0x81, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, 0x02200000, 0)
		if err != nil {
			return locks, errPackage
		}
		locks = append(locks, h)
		var info syscall.ByHandleFileInformation
		if syscall.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return locks, errPackage
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	return locks, nil
}

func lockPayloads(root string, names []string) ([]syscall.Handle, error) {
	var locks []syscall.Handle
	for _, name := range names {
		path, err := memberPath(root, name)
		if err != nil {
			return locks, err
		}
		dirs, err := lockParents(filepath.Dir(path))
		locks = append(locks, dirs...)
		if err != nil {
			return locks, err
		}
		p, _ := syscall.UTF16PtrFromString(path)
		h, err := syscall.CreateFile(p, syscall.GENERIC_READ, syscall.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING, 0x00200000, 0)
		if err != nil {
			return locks, errPackage
		}
		locks = append(locks, h)
		var info syscall.ByHandleFileInformation
		if syscall.GetFileInformationByHandle(h, &info) != nil || info.NumberOfLinks != 1 || info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return locks, errPackage
		}
	}
	return locks, nil
}

func launch(source string, m manifest, data []byte) error {
	parent := os.Getenv("LOCALAPPDATA")
	if !filepath.IsAbs(parent) {
		return errPackage
	}
	locks, err := lockParents(parent)
	defer func() {
		for _, h := range locks {
			_ = syscall.CloseHandle(h)
		}
	}()
	if err != nil {
		return err
	}
	root, err := newPrivateCache(parent)
	if err != nil {
		return err
	}
	cacheLocks, err := lockParents(root)
	defer func() {
		for _, h := range cacheLocks {
			_ = syscall.CloseHandle(h)
		}
	}()
	if err != nil {
		return err
	}
	// New private files receive only verified bytes. This does not change an
	// existing file's zone, ACL or machine PowerShell policy. AllSigned still
	// refuses unsigned scripts; no ExecutionPolicy override is used.
	names := make([]string, 0, len(m.Files))
	for name := range m.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		src, err := memberPath(source, name)
		if err != nil {
			return err
		}
		dst := filepath.Join(root, filepath.FromSlash(name))
		if os.MkdirAll(filepath.Dir(dst), 0700) != nil {
			return errPackage
		} // ACL is inherited from private NTFS root.
		in, err := os.Open(src)
		if err != nil {
			return errPackage
		}
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			_ = in.Close()
			return errPackage
		}
		h := sha256.New()
		_, copyErr := io.Copy(io.MultiWriter(out, h), in)
		_ = in.Close()
		closeErr := out.Close()
		if copyErr != nil || closeErr != nil || hex.EncodeToString(h.Sum(nil)) != m.Files[name] {
			return errPackage
		}
	}
	if os.WriteFile(filepath.Join(root, "release-manifest.json"), data, 0600) != nil {
		return errPackage
	}
	if _, err = verifyPackage(root, data); err != nil {
		return err
	}
	// Keep the verified executable inputs and their directories stable until
	// PowerShell exits. No existing installation files are held by this launcher.
	payloadLocks, err := lockPayloads(root, append(names, "release-manifest.json"))
	defer func() {
		for _, h := range payloadLocks {
			_ = syscall.CloseHandle(h)
		}
	}()
	if err != nil {
		return err
	}
	if _, err = verifyPackage(root, data); err != nil {
		return err
	}
	ps := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	cmd := exec.Command(ps, "-NoProfile", "-STA", "-File", filepath.Join(root, "Setup-FileBridge.ps1"), "-Run", "-ReleaseDirectory", root)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	// The UI owns bounded diagnostics; never echo PowerShell stderr/tracebacks.
	if cmd.Run() != nil {
		return errors.New("CF_SETUP_STOPPED_SEE_PRIVATE_SETUP_REPORT")
	}
	return nil
}

func showFailure(err error) {
	message := err.Error()
	fmt.Fprintln(os.Stderr, message)
	if len(os.Args) == 2 && os.Args[1] == "--verify-package" {
		return
	}
	text, _ := syscall.UTF16PtrFromString("FileBridge setup stopped safely.\n" + message + "\nExisting files and interrupted transactions have been preserved.")
	title, _ := syscall.UTF16PtrFromString("FileBridge Setup")
	_, _, _ = syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(title)), 0x10)
}
