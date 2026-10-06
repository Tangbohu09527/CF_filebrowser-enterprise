//go:build linux

package inbound

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

type fileIdentity struct {
	device uint64
	inode  uint64
}
type storeBackend struct {
	directory string
	root      *os.Root
	locks     []*os.File
	identity  fileIdentity
}

func linuxIdentity(f *os.File) (fileIdentity, os.FileInfo, error) {
	info, err := f.Stat()
	if err != nil {
		return fileIdentity{}, nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileIdentity{}, nil, errStore
	}
	return fileIdentity{uint64(stat.Dev), stat.Ino}, info, nil
}

func openStoreBackend(directory string) (*storeBackend, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || directory == "/" {
		return nil, errStore
	}
	b := &storeBackend{directory: directory}
	fail := func() (*storeBackend, error) { _ = b.close(); return nil, errStore }
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fail()
	}
	b.locks = append(b.locks, os.NewFile(uintptr(fd), "/"))
	for _, part := range strings.Split(directory[1:], "/") {
		fd, err = syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return fail()
		}
		b.locks = append(b.locks, os.NewFile(uintptr(fd), part))
	}
	final := b.locks[len(b.locks)-1]
	id, info, err := linuxIdentity(final)
	if err != nil || info.Mode().Perm() != 0700 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return fail()
	}
	b.identity = id
	// os.Root keeps all file operations anchored after authorization. Check
	// its selected object against the no-follow chain before exposing it.
	b.root, err = os.OpenRoot(directory)
	if err != nil {
		return fail()
	}
	rf, err := b.root.Open(".")
	if err != nil {
		return fail()
	}
	rid, _, err := linuxIdentity(rf)
	_ = rf.Close()
	if err != nil || rid != id {
		return fail()
	}
	return b, nil
}

func (b *storeBackend) verify() error {
	if b.root == nil {
		return errStore
	}
	f, err := b.root.Open(".")
	if err != nil {
		return errStore
	}
	defer f.Close()
	id, info, err := linuxIdentity(f)
	if err != nil || id != b.identity || info.Mode().Perm() != 0700 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return errStore
	}
	return nil
}

func (b *storeBackend) create(name string) (*os.File, fileIdentity, error) {
	// Anonymous staging eliminates the lstat/unlink race entirely: there is
	// no temporary name that another process could replace before cleanup.
	// Filesystems without O_TMPFILE support fail closed, never fall back to
	// creating and later unlinking an attacker-replaceable pathname.
	dirfd := int(b.locks[len(b.locks)-1].Fd())
	const oTmpfile = 0x400000 | syscall.O_DIRECTORY
	fd, err := syscall.Openat(dirfd, ".", syscall.O_RDWR|syscall.O_CLOEXEC|oTmpfile, 0600)
	if err != nil {
		return nil, fileIdentity{}, errStore
	}
	f := os.NewFile(uintptr(fd), filepath.Join(b.directory, name))
	id, info, err := linuxIdentity(f)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		_ = f.Close()
		return nil, fileIdentity{}, errStore
	}
	return f, id, nil
}

func (b *storeBackend) publish(f *os.File, old, name string, id fileIdentity) error {
	actual, info, err := linuxIdentity(f)
	if err != nil || actual != id || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return errStore
	}
	// Publish the exact held inode, with linkat's no-replacement semantics.
	// /proc/self/fd permits unprivileged linking of an owned O_TMPFILE inode;
	// AT_EMPTY_PATH would instead require CAP_DAC_READ_SEARCH. The destination
	// is relative to the held directory handle, never the original path.
	source, err := syscall.BytePtrFromString("/proc/self/fd/" + strconv.FormatUint(uint64(f.Fd()), 10))
	if err != nil {
		return errStore
	}
	destination, err := syscall.BytePtrFromString(name)
	if err != nil {
		return errStore
	}
	const atSymlinkFollow = 0x400
	// AT_FDCWD is -100 represented in an unsigned syscall argument.
	atFDCWD := ^uintptr(99)
	_, _, errno := syscall.Syscall6(syscall.SYS_LINKAT, atFDCWD, uintptr(unsafe.Pointer(source)), b.locks[len(b.locks)-1].Fd(), uintptr(unsafe.Pointer(destination)), atSymlinkFollow, 0)
	if errno != 0 {
		return errStore
	}
	return nil
}

func (b *storeBackend) abort(f *os.File, name string, id fileIdentity) error {
	// Staging.Close destroys an unpublished anonymous inode. If cancellation
	// wins after publication, retain the complete verified file without issuing
	// a handle. Linux has no safe unlink-by-open-handle operation: never guess
	// that a pathname still refers to an owned file and delete an unknown one.
	return nil
}

func (b *storeBackend) open(name string, id fileIdentity) (*os.File, error) {
	f, err := b.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errStore
	}
	actual, info, err := linuxIdentity(f)
	if err != nil || actual != id || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		_ = f.Close()
		return nil, errStore
	}
	return f, nil
}

func (b *storeBackend) close() error {
	var first error
	if b.root != nil {
		first = b.root.Close()
		b.root = nil
	}
	for _, f := range b.locks {
		if err := f.Close(); err != nil && first == nil {
			first = err
		}
	}
	b.locks = nil
	return first
}
