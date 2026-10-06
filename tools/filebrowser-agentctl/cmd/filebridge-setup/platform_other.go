//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os"
)

func isReparse(os.FileInfo) bool            { return false }
func launch(string, manifest, []byte) error { return errors.New("CF_SETUP_WINDOWS_REQUIRED") }
func showFailure(err error)                 { fmt.Fprintln(os.Stderr, err.Error()) }
