package trash

import (
	"os"

	"golang.org/x/sys/unix"
)

// Renameat2 provides an atomic, same-filesystem, no-overwrite move. EXDEV and
// unsupported filesystems fail closed; no copy or system-disk staging is used.
func moveNoReplace(root *os.Root, oldPath, newPath string) error {
	from, old, err := safeParent(root, oldPath)
	if err != nil {
		return err
	}
	defer from.Close()
	to, name, err := safeParent(root, newPath)
	if err != nil {
		return err
	}
	defer to.Close()
	a, err := from.Open(".")
	if err != nil {
		return err
	}
	defer a.Close()
	b, err := to.Open(".")
	if err != nil {
		return err
	}
	defer b.Close()
	return unix.Renameat2(int(a.Fd()), old, int(b.Fd()), name, unix.RENAME_NOREPLACE)
}
