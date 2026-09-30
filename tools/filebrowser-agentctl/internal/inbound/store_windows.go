//go:build windows

package inbound

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const (
	readControl        = 0x00020000
	deleteAccess       = 0x00010000
	openReparsePoint   = 0x00200000
	backupSemantics    = 0x02000000
	fileReadAttributes = 0x00000080
	fileListDirectory  = 0x00000001
)

var (
	storeAdvapi          = syscall.NewLazyDLL("advapi32.dll")
	storeKernel          = syscall.NewLazyDLL("kernel32.dll")
	getSecurityInfo      = storeAdvapi.NewProc("GetSecurityInfo")
	getSecurityControl   = storeAdvapi.NewProc("GetSecurityDescriptorControl")
	getSecurityDACL      = storeAdvapi.NewProc("GetSecurityDescriptorDacl")
	getACE               = storeAdvapi.NewProc("GetAce")
	validSID             = storeAdvapi.NewProc("IsValidSid")
	convertSDDL          = storeAdvapi.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	setSecurityInfo      = storeAdvapi.NewProc("SetSecurityInfo")
	setFileInformation   = storeKernel.NewProc("SetFileInformationByHandle")
	getVolumeInformation = storeKernel.NewProc("GetVolumeInformationByHandleW")
)

type fileIdentity struct{ volume, high, low uint32 }
type lockedDirectory struct {
	handle   syscall.Handle
	identity fileIdentity
}
type storeBackend struct {
	directory string
	locks     []lockedDirectory
	userSID   string
}

func identityOf(h syscall.Handle) (fileIdentity, uint32, error) {
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(h, &info); err != nil {
		return fileIdentity{}, 0, err
	}
	return fileIdentity{info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow}, info.FileAttributes, nil
}

func currentStoreSID() (string, error) {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return "", err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String()
}

func privateStoreDescriptor(sid string) (uintptr, error) {
	sddl, err := syscall.UTF16PtrFromString("O:" + sid + "D:P(A;OICI;FA;;;" + sid + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return 0, err
	}
	var sd uintptr
	ok, _, _ := convertSDDL.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&sd)), 0)
	if ok == 0 {
		return 0, errStore
	}
	return sd, nil
}

// validatePrivateACL inspects the actual open object, not a path that could be
// replaced. Unknown ACE forms and principals fail closed. Windows mode bits do
// not represent NTFS protection and are deliberately unused.
func validatePrivateACL(h syscall.Handle, userSID string) error {
	var owner, dacl, sd unsafe.Pointer
	r, _, _ := getSecurityInfo.Call(uintptr(h), 1, 5, uintptr(unsafe.Pointer(&owner)), 0, uintptr(unsafe.Pointer(&dacl)), 0, uintptr(unsafe.Pointer(&sd)))
	if r != 0 {
		return errStore
	}
	defer syscall.LocalFree(syscall.Handle(uintptr(sd)))
	allowed := func(sid unsafe.Pointer) bool {
		ok, _, _ := validSID.Call(uintptr(sid))
		if ok == 0 {
			return false
		}
		s, err := (*syscall.SID)(sid).String()
		return err == nil && (s == userSID || s == "S-1-5-18" || s == "S-1-5-32-544")
	}
	if owner == nil || !allowed(owner) || dacl == nil {
		return errStore
	}
	var control uint16
	var revision uint32
	ok, _, _ := getSecurityControl.Call(uintptr(sd), uintptr(unsafe.Pointer(&control)), uintptr(unsafe.Pointer(&revision)))
	if ok == 0 || control&0x1000 == 0 {
		return errStore
	}
	header := unsafe.Slice((*byte)(dacl), 8)
	count := binary.LittleEndian.Uint16(header[4:6])
	if count == 0 {
		return errStore
	}
	for i := uint16(0); i < count; i++ {
		var ace unsafe.Pointer
		ok, _, _ = getACE.Call(uintptr(dacl), uintptr(i), uintptr(unsafe.Pointer(&ace)))
		if ok == 0 || ace == nil {
			return errStore
		}
		h := unsafe.Slice((*byte)(ace), 8)
		if h[0] != 0 || binary.LittleEndian.Uint16(h[2:4]) < 16 || !allowed(unsafe.Add(ace, 8)) {
			return errStore
		}
	}
	return nil
}

func windowsStorePath(directory string) bool {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || strings.ContainsAny(directory, "/\x00") {
		return false
	}
	volume := filepath.VolumeName(directory)
	if len(volume) != 2 || volume[1] != ':' || len(directory) <= 3 || strings.Contains(directory[2:], ":") {
		return false
	}
	for _, part := range strings.Split(directory[3:], `\`) {
		if part == "" || strings.TrimRight(part, ". ") != part || strings.ContainsAny(part, `<>"|?*`) {
			return false
		}
		base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || (len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9') {
			return false
		}
	}
	return true
}

func openStoreBackend(directory string) (*storeBackend, error) {
	if !windowsStorePath(directory) {
		return nil, errStore
	}
	sid, err := currentStoreSID()
	if err != nil {
		return nil, errStore
	}
	b := &storeBackend{directory: directory, userSID: sid}
	fail := func() (*storeBackend, error) { _ = b.close(); return nil, errStore }
	// Lock root and every ancestor without FILE_SHARE_DELETE. A path component
	// cannot be renamed/replaced while the store is open. OPEN_REPARSE_POINT
	// makes each inspection act on the junction/symlink itself.
	paths := []string{directory[:3]}
	for _, part := range strings.Split(directory[3:], `\`) {
		paths = append(paths, filepath.Join(paths[len(paths)-1], part))
	}
	for _, path := range paths {
		p, _ := syscall.UTF16PtrFromString(path)
		// Metadata-only handles do not participate in Windows share access
		// checks. FILE_LIST_DIRECTORY is required to actually block deletion.
		h, err := syscall.CreateFile(p, readControl|fileReadAttributes|fileListDirectory, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, openReparsePoint|backupSemantics, 0)
		if err != nil {
			return fail()
		}
		id, attrs, err := identityOf(h)
		if err != nil || attrs&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 || attrs&syscall.FILE_ATTRIBUTE_DIRECTORY == 0 {
			_ = syscall.CloseHandle(h)
			return fail()
		}
		b.locks = append(b.locks, lockedDirectory{h, id})
	}
	last := b.locks[len(b.locks)-1].handle
	var fs [32]uint16
	ok, _, _ := getVolumeInformation.Call(uintptr(last), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&fs[0])), uintptr(len(fs)))
	if ok == 0 || syscall.UTF16ToString(fs[:]) != "NTFS" || validatePrivateACL(last, sid) != nil {
		return fail()
	}
	return b, nil
}

func (b *storeBackend) verify() error {
	if len(b.locks) == 0 {
		return errStore
	}
	for _, lock := range b.locks {
		id, attrs, err := identityOf(lock.handle)
		if err != nil || id != lock.identity || attrs&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 || attrs&syscall.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return errStore
		}
	}
	return validatePrivateACL(b.locks[len(b.locks)-1].handle, b.userSID)
}

func (b *storeBackend) create(name string) (*os.File, fileIdentity, error) {
	sd, err := privateStoreDescriptor(b.userSID)
	if err != nil {
		return nil, fileIdentity{}, err
	}
	defer syscall.LocalFree(syscall.Handle(sd))
	sa := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: sd}
	path := filepath.Join(b.directory, name)
	p, _ := syscall.UTF16PtrFromString(path)
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ|syscall.GENERIC_WRITE|deleteAccess|readControl, syscall.FILE_SHARE_READ, &sa, syscall.CREATE_NEW, openReparsePoint|syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, fileIdentity{}, errStore
	}
	f := os.NewFile(uintptr(h), path)
	id, attrs, err := identityOf(h)
	if err != nil || attrs&(syscall.FILE_ATTRIBUTE_DIRECTORY|syscall.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || validatePrivateACL(h, b.userSID) != nil {
		_ = f.Close()
		return nil, fileIdentity{}, errStore
	}
	return f, id, nil
}

func (b *storeBackend) publish(f *os.File, old, name string, id fileIdentity) error {
	actual, attrs, err := identityOf(syscall.Handle(f.Fd()))
	if err != nil || actual != id || attrs&(syscall.FILE_ATTRIBUTE_DIRECTORY|syscall.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || validatePrivateACL(syscall.Handle(f.Fd()), b.userSID) != nil {
		return errStore
	}
	path, err := syscall.UTF16FromString(filepath.Join(b.directory, name))
	if err != nil {
		return errStore
	}
	path = path[:len(path)-1]
	// FILE_RENAME_INFO has pointer-sized alignment after ReplaceIfExists.
	rootOffset := unsafe.Sizeof(uintptr(0))
	lengthOffset := rootOffset * 2
	nameOffset := lengthOffset + 4
	buffer := make([]byte, int(nameOffset)+len(path)*2)
	binary.LittleEndian.PutUint32(buffer[lengthOffset:], uint32(len(path)*2))
	for i, u := range path {
		binary.LittleEndian.PutUint16(buffer[int(nameOffset)+i*2:], u)
	}
	ok, _, _ := setFileInformation.Call(f.Fd(), 3, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	if ok == 0 {
		return errStore
	}
	return nil
}

func (b *storeBackend) abort(f *os.File, name string, id fileIdentity) error {
	h := syscall.Handle(f.Fd())
	actual, _, err := identityOf(h)
	if err != nil {
		// A caller may already have closed the writer. Reopen and compare its
		// stable file ID; never remove whatever happens to occupy the name.
		p, _ := syscall.UTF16PtrFromString(filepath.Join(b.directory, name))
		h, err = syscall.CreateFile(p, deleteAccess|readControl|fileReadAttributes, syscall.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING, openReparsePoint, 0)
		if err == syscall.ERROR_FILE_NOT_FOUND {
			return nil
		}
		if err != nil {
			return errStore
		}
		defer syscall.CloseHandle(h)
		actual, _, err = identityOf(h)
	}
	if err != nil || actual != id {
		return errStore
	}
	remove := uint32(1)
	ok, _, _ := setFileInformation.Call(uintptr(h), 4, uintptr(unsafe.Pointer(&remove)), 4)
	if ok == 0 {
		return errStore
	}
	return nil
}

func (b *storeBackend) open(name string, id fileIdentity) (*os.File, error) {
	path := filepath.Join(b.directory, name)
	p, _ := syscall.UTF16PtrFromString(path)
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ|readControl, syscall.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING, openReparsePoint, 0)
	if err != nil {
		return nil, errStore
	}
	actual, attrs, err := identityOf(h)
	if err != nil || actual != id || attrs&(syscall.FILE_ATTRIBUTE_DIRECTORY|syscall.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || validatePrivateACL(h, b.userSID) != nil {
		_ = syscall.CloseHandle(h)
		return nil, errStore
	}
	return os.NewFile(uintptr(h), path), nil
}

func (b *storeBackend) close() error {
	var first error
	for i := len(b.locks) - 1; i >= 0; i-- {
		if err := syscall.CloseHandle(b.locks[i].handle); err != nil && first == nil {
			first = err
		}
	}
	b.locks = nil
	return first
}
