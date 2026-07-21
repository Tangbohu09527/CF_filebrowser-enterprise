//go:build !windows && !linux && !darwin

package http

import "os"

func renameWebDAVNoReplace(_, _ string) error {
	return os.ErrPermission
}
