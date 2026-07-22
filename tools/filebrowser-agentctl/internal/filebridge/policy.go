package filebridge

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

type accessMode string

const (
	readAccess         accessMode = "read"
	writeAccess        accessMode = "write"
	maxRemotePathBytes            = 4096
)

func normalizeRemoteRoots(roots []string) ([]string, error) {
	normalized := make([]string, 0, len(roots))
	seen := make(map[string]struct{}, len(roots))
	for _, root := range roots {
		value, err := normalizeRemotePath(root)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized, nil
}

func normalizeRemotePath(value string) (string, error) {
	if value == "" || len(value) > maxRemotePathBytes || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") ||
		strings.ContainsAny(value, "\\\x00\r\n") {
		return "", fmt.Errorf("invalid remote path")
	}
	withoutRoot := strings.TrimPrefix(value, "/")
	if len(withoutRoot) >= 2 && withoutRoot[1] == ':' {
		return "", fmt.Errorf("physical drive path is not allowed")
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "." || segment == ".." {
			return "", fmt.Errorf("path traversal is not allowed")
		}
	}
	cleaned := path.Clean(value)
	if cleaned == "." || !strings.HasPrefix(cleaned, "/") {
		return "", fmt.Errorf("invalid remote path")
	}
	return cleaned, nil
}

func (c *Config) authorizeRemote(source, requestedPath string, mode accessMode) (string, error) {
	policy, ok := c.AllowedSources[source]
	if !ok {
		return "", bridgeError("source_denied", "source is not in the local allowlist")
	}
	normalized, err := normalizeRemotePath(requestedPath)
	if err != nil {
		return "", bridgeError("invalid_path", "path must be an absolute logical path without traversal, backslashes, or physical path syntax")
	}
	roots := policy.ReadRoots
	if mode == writeAccess {
		roots = policy.WriteRoots
	}
	for _, root := range roots {
		if remotePathWithin(root, normalized) {
			return normalized, nil
		}
	}
	return "", bridgeError("path_denied", fmt.Sprintf("path is outside locally allowed %s roots", mode))
}

func remotePathWithin(root, target string) bool {
	return root == "/" || target == root || strings.HasPrefix(target, strings.TrimSuffix(root, "/")+"/")
}

func joinRemote(parent, child string) (string, error) {
	if strings.ContainsAny(child, "/\\\x00\r\n") || child == "" || child == "." || child == ".." {
		return "", fmt.Errorf("invalid item name")
	}
	return normalizeRemotePath(path.Join(parent, child))
}

func (c *Config) authorizeLocalRead(filename string) (string, error) {
	if len(c.LocalReadRoots) == 0 {
		return "", bridgeError("local_path_denied", "local_read_roots is empty")
	}
	resolved, err := filepath.EvalSymlinks(filename)
	if err != nil {
		return "", bridgeError("local_file_unavailable", "local_file cannot be resolved")
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		return "", bridgeError("local_file_unavailable", "local_file path is invalid")
	}
	if !pathWithinAnyLocalRoot(abs, c.LocalReadRoots) {
		return "", bridgeError("local_path_denied", "local_file is outside local_read_roots")
	}
	info, err := os.Stat(abs)
	if err != nil || !info.Mode().IsRegular() {
		return "", bridgeError("local_file_unavailable", "local_file must be a regular file")
	}
	return abs, nil
}

func (c *Config) authorizeLocalWrite(filename string) (string, error) {
	if len(c.LocalWriteRoots) == 0 {
		return "", bridgeError("local_path_denied", "local_write_roots is empty")
	}
	abs, err := filepath.Abs(filename)
	if err != nil || filepath.Base(abs) == "." {
		return "", bridgeError("invalid_output_file", "output_file path is invalid")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", bridgeError("invalid_output_file", "output_file parent must exist")
	}
	target := filepath.Join(parent, filepath.Base(abs))
	if !pathWithinAnyLocalRoot(target, c.LocalWriteRoots) {
		return "", bridgeError("local_path_denied", "output_file is outside local_write_roots")
	}
	if _, err := os.Lstat(target); err == nil {
		return "", bridgeError("local_target_exists", "output_file already exists")
	} else if !os.IsNotExist(err) {
		return "", bridgeError("invalid_output_file", "output_file cannot be inspected")
	}
	return target, nil
}

func pathWithinAnyLocalRoot(target string, roots []string) bool {
	for _, configuredRoot := range roots {
		root, err := filepath.EvalSymlinks(configuredRoot)
		if err != nil {
			continue
		}
		root, err = filepath.Abs(root)
		if err == nil && localPathWithin(root, target) {
			return true
		}
	}
	return false
}

func localPathWithin(root, target string) bool {
	relative, err := filepath.Rel(root, target)
	if err != nil || filepath.IsAbs(relative) {
		return false
	}
	if runtime.GOOS == "windows" {
		relative = strings.ToLower(relative)
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
