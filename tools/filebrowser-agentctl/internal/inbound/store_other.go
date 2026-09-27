//go:build !windows && !linux

package inbound

import "os"

// Platforms without an audited native store implementation fail closed.
type fileIdentity struct{}
type storeBackend struct{}

func openStoreBackend(string) (*storeBackend, error) { return nil, errStore }
func (*storeBackend) verify() error                  { return errStore }
func (*storeBackend) create(string) (*os.File, fileIdentity, error) {
	return nil, fileIdentity{}, errStore
}
func (*storeBackend) publish(*os.File, string, string, fileIdentity) error { return errStore }
func (*storeBackend) abort(*os.File, string, fileIdentity) error           { return errStore }
func (*storeBackend) open(string, fileIdentity) (*os.File, error)          { return nil, errStore }
func (*storeBackend) close() error                                         { return nil }
