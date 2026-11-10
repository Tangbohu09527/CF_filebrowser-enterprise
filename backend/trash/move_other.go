//go:build !linux

package trash

import "os"

// A no-overwrite hard link followed by unlink is recoverable if interrupted.
// Both names remain recorded as pending until reconciliation; EXDEV fails closed.
func moveNoReplace(root *os.Root, old, name string) error {
	if err := root.Link(old, name); err != nil {
		return err
	}
	return root.Remove(old)
}
