package http

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/fileutils"
	commonerrors "github.com/gtsteffaniak/filebrowser/backend/common/errors"
	"github.com/gtsteffaniak/filebrowser/backend/common/utils"
	"github.com/gtsteffaniak/go-logger/logger"
)

const (
	chunkUploadTempTTL         = 24 * time.Hour
	chunkUploadTempMarker      = ".fbc-"
	chunkUploadTempSuffix      = ".uploading.tmp"
	chunkUploadSessionKeyBytes = 10
	chunkUploadNonceBytes      = 10
	chunkUploadAuthTagBytes    = 12
	chunkUploadTempTokenLen    = 43 // raw base64url of the 32 bytes above
	chunkUploadPauseKeySep     = "\x1e"
)

type chunkUploadTargetLock struct {
	mu   sync.Mutex
	refs int
}

var chunkUploadTargetLocks = struct {
	sync.Mutex
	entries map[string]*chunkUploadTargetLock
}{
	entries: make(map[string]*chunkUploadTargetLock),
}

var chunkUploadCleanupTimers = struct {
	sync.Mutex
	entries map[string]*time.Timer
}{
	entries: make(map[string]*time.Timer),
}

type chunkUploadTemp struct {
	path       string
	sessionKey string
}

func chunkUploadPrincipal(d *requestContext) string {
	if d.share != nil {
		return "share:" + d.share.Hash
	}
	return "user:" + strconv.FormatUint(uint64(d.user.ID), 10)
}

func chunkUploadPauseKey(d *requestContext, source, path string) string {
	return chunkUploadPrincipal(d) + chunkUploadPauseKeySep + source + chunkUploadPauseKeySep + path
}

func chunkUploadTargetKey(targetPath string) string {
	key := filepath.Clean(targetPath)
	if runtime.GOOS == "windows" {
		key = strings.ToLower(key)
	}
	return key
}

func lockChunkUploadTarget(targetPath string) func() {
	key := chunkUploadTargetKey(targetPath)

	chunkUploadTargetLocks.Lock()
	targetLock := chunkUploadTargetLocks.entries[key]
	if targetLock == nil {
		targetLock = &chunkUploadTargetLock{}
		chunkUploadTargetLocks.entries[key] = targetLock
	}
	targetLock.refs++
	chunkUploadTargetLocks.Unlock()

	targetLock.mu.Lock()
	return func() {
		unlockChunkUploadTarget(key, targetLock)
	}
}

// tryLockChunkUploadTarget reserves an idle target for stale-file cleanup.
func tryLockChunkUploadTarget(targetPath string) (func(), bool) {
	key := chunkUploadTargetKey(targetPath)

	chunkUploadTargetLocks.Lock()
	if _, active := chunkUploadTargetLocks.entries[key]; active {
		chunkUploadTargetLocks.Unlock()
		return nil, false
	}
	targetLock := &chunkUploadTargetLock{refs: 1}
	targetLock.mu.Lock()
	chunkUploadTargetLocks.entries[key] = targetLock
	chunkUploadTargetLocks.Unlock()

	return func() {
		unlockChunkUploadTarget(key, targetLock)
	}, true
}

func unlockChunkUploadTarget(key string, targetLock *chunkUploadTargetLock) {
	targetLock.mu.Unlock()

	chunkUploadTargetLocks.Lock()
	targetLock.refs--
	if targetLock.refs == 0 {
		delete(chunkUploadTargetLocks.entries, key)
	}
	chunkUploadTargetLocks.Unlock()
}

func chunkUploadSessionKey(principal, targetPath string, totalSize int64) string {
	key := principal + "\x00" + chunkUploadTargetKey(targetPath) + "\x00" + strconv.FormatInt(totalSize, 10)
	sum := sha256.Sum256([]byte(key))
	return base64.RawURLEncoding.EncodeToString(sum[:chunkUploadSessionKeyBytes])
}

func chunkUploadAuthenticationKey() ([]byte, error) {
	if store != nil && store.Settings != nil {
		persisted, err := store.Settings.Get()
		if err == nil && persisted.Auth.Key != "" {
			return []byte(persisted.Auth.Key), nil
		}
		if err != nil && err != commonerrors.ErrNotExist {
			return nil, fmt.Errorf("could not load persisted chunk upload authentication key: %w", err)
		}
	}

	if config != nil && config.Auth.Key != "" {
		return []byte(config.Auth.Key), nil
	}
	return nil, fmt.Errorf("chunk upload authentication key is not configured")
}

func chunkUploadAuthenticationTag(targetPath string, sessionKey, nonce []byte) ([]byte, error) {
	key, err := chunkUploadAuthenticationKey()
	if err != nil {
		return nil, err
	}

	mac := hmac.New(sha256.New, key)
	_, _ = io.WriteString(mac, chunkUploadTargetKey(targetPath))
	_, _ = io.WriteString(mac, "\x00")
	_, _ = mac.Write(sessionKey)
	_, _ = io.WriteString(mac, "\x00")
	_, _ = mac.Write(nonce)
	return mac.Sum(nil)[:chunkUploadAuthTagBytes], nil
}

func newChunkUploadTempToken(targetPath, sessionKey string) (string, error) {
	sessionKeyBytes, err := base64.RawURLEncoding.DecodeString(sessionKey)
	if err != nil || len(sessionKeyBytes) != chunkUploadSessionKeyBytes {
		return "", fmt.Errorf("invalid chunk upload session key")
	}

	nonceHex, err := utils.RandomHex(chunkUploadNonceBytes)
	if err != nil {
		return "", err
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return "", err
	}
	authTag, err := chunkUploadAuthenticationTag(targetPath, sessionKeyBytes, nonce)
	if err != nil {
		return "", err
	}

	token := make([]byte, 0, chunkUploadSessionKeyBytes+chunkUploadNonceBytes+chunkUploadAuthTagBytes)
	token = append(token, sessionKeyBytes...)
	token = append(token, nonce...)
	token = append(token, authTag...)
	return base64.RawURLEncoding.EncodeToString(token), nil
}

func openChunkUploadFile(targetPath, principal string, offset, totalSize int64) (*os.File, string, bool, int, error) {
	temps, err := chunkUploadTempsForTarget(targetPath)
	if err != nil {
		return nil, "", false, http.StatusInternalServerError, fmt.Errorf("could not inspect chunk upload state: %v", err)
	}

	sessionKey := chunkUploadSessionKey(principal, targetPath, totalSize)
	created := false
	tempFilePath := ""
	var outFile *os.File

	if offset == 0 {
		if len(temps) != 0 {
			return nil, "", false, http.StatusConflict, fmt.Errorf("an upload is already active for this target")
		}

		for attempts := 0; attempts < 3; attempts++ {
			token, tokenErr := newChunkUploadTempToken(targetPath, sessionKey)
			if tokenErr != nil {
				return nil, "", false, http.StatusInternalServerError, fmt.Errorf("could not create chunk upload session: %v", tokenErr)
			}
			tempFilePath = targetPath + chunkUploadTempMarker + token + chunkUploadTempSuffix
			outFile, err = os.OpenFile(tempFilePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, fileutils.PermFile)
			if err == nil {
				created = true
				break
			}
			if !os.IsExist(err) {
				return nil, "", false, http.StatusInternalServerError, fmt.Errorf("could not create chunk upload file: %v", err)
			}
		}
		if outFile == nil {
			return nil, "", false, http.StatusConflict, fmt.Errorf("could not allocate a unique chunk upload session")
		}
	} else {
		if len(temps) != 1 || temps[0].sessionKey != sessionKey {
			return nil, "", false, http.StatusConflict, fmt.Errorf("no matching chunk upload session")
		}

		tempFilePath = temps[0].path
		fileInfo, statErr := os.Lstat(tempFilePath)
		if statErr != nil {
			return nil, "", false, http.StatusConflict, fmt.Errorf("chunk upload session is no longer available")
		}
		if !fileInfo.Mode().IsRegular() {
			return nil, "", false, http.StatusConflict, fmt.Errorf("chunk upload session is invalid")
		}
		outFile, err = os.OpenFile(tempFilePath, os.O_WRONLY, fileutils.PermFile)
		if err != nil {
			return nil, "", false, http.StatusInternalServerError, fmt.Errorf("could not open chunk upload file: %v", err)
		}
	}

	fileInfo, err := outFile.Stat()
	if err != nil {
		_ = outFile.Close()
		if created {
			removeChunkUploadTemp(tempFilePath)
		}
		return nil, "", false, http.StatusInternalServerError, fmt.Errorf("could not inspect chunk upload file: %v", err)
	}
	if !fileInfo.Mode().IsRegular() || fileInfo.Size() != offset {
		_ = outFile.Close()
		if created {
			removeChunkUploadTemp(tempFilePath)
		}
		return nil, "", false, http.StatusConflict, fmt.Errorf("chunk offset does not match the received length")
	}
	if _, err = outFile.Seek(offset, io.SeekStart); err != nil {
		_ = outFile.Close()
		if created {
			removeChunkUploadTemp(tempFilePath)
		}
		return nil, "", false, http.StatusInternalServerError, fmt.Errorf("could not seek in chunk upload file: %v", err)
	}

	return outFile, tempFilePath, created, http.StatusOK, nil
}

func copyChunkUploadBody(dst io.Writer, src io.Reader, remaining int64) (int64, bool, error) {
	limit := remaining
	if remaining < math.MaxInt64 {
		limit++
	}

	written, err := io.Copy(dst, io.LimitReader(src, limit))
	return written, written > remaining, err
}

func resetChunkUploadFile(file *os.File, offset int64) error {
	if err := file.Truncate(offset); err != nil {
		return err
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return err
	}
	return file.Sync()
}

func scheduleChunkUploadTempCleanup(targetPath, tempFilePath string) {
	scheduleChunkUploadTempCleanupAfter(targetPath, tempFilePath, chunkUploadTempTTL)
}

func scheduleChunkUploadTempCleanupAfter(targetPath, tempFilePath string, delay time.Duration) {
	var timer *time.Timer
	timer = time.AfterFunc(delay, func() {
		expireChunkUploadTemp(targetPath, tempFilePath, timer)
	})

	chunkUploadCleanupTimers.Lock()
	previous := chunkUploadCleanupTimers.entries[tempFilePath]
	chunkUploadCleanupTimers.entries[tempFilePath] = timer
	chunkUploadCleanupTimers.Unlock()
	if previous != nil {
		previous.Stop()
	}
}

func expireChunkUploadTemp(targetPath, tempFilePath string, timer *time.Timer) {
	chunkUploadCleanupTimers.Lock()
	if chunkUploadCleanupTimers.entries[tempFilePath] != timer {
		chunkUploadCleanupTimers.Unlock()
		return
	}
	chunkUploadCleanupTimers.Unlock()

	unlockTarget := lockChunkUploadTarget(targetPath)
	defer unlockTarget()

	chunkUploadCleanupTimers.Lock()
	if chunkUploadCleanupTimers.entries[tempFilePath] != timer {
		chunkUploadCleanupTimers.Unlock()
		return
	}
	chunkUploadCleanupTimers.Unlock()

	directory := filepath.Dir(tempFilePath)
	parsedTarget, _, ok := parseChunkUploadTempName(directory, filepath.Base(tempFilePath))
	if !ok || chunkUploadTargetKey(filepath.Join(directory, parsedTarget)) != chunkUploadTargetKey(targetPath) {
		stopChunkUploadTempCleanup(tempFilePath)
		return
	}

	info, err := os.Lstat(tempFilePath)
	if err != nil || !info.Mode().IsRegular() {
		stopChunkUploadTempCleanup(tempFilePath)
		return
	}
	age := time.Since(info.ModTime())
	if age < chunkUploadTempTTL {
		delay := chunkUploadTempTTL - age
		if delay > chunkUploadTempTTL {
			delay = chunkUploadTempTTL
		}
		scheduleChunkUploadTempCleanupAfter(targetPath, tempFilePath, delay)
		return
	}
	removeChunkUploadTemp(tempFilePath)
}

func stopChunkUploadTempCleanup(tempFilePath string) {
	chunkUploadCleanupTimers.Lock()
	timer := chunkUploadCleanupTimers.entries[tempFilePath]
	delete(chunkUploadCleanupTimers.entries, tempFilePath)
	chunkUploadCleanupTimers.Unlock()
	if timer != nil {
		timer.Stop()
	}
}

func chunkUploadTempsForTarget(targetPath string) ([]chunkUploadTemp, error) {
	directory := filepath.Dir(targetPath)
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}

	targetKey := chunkUploadTargetKey(targetPath)
	temps := make([]chunkUploadTemp, 0, 1)
	for _, entry := range entries {
		parsedTarget, sessionKey, ok := parseChunkUploadTempName(directory, entry.Name())
		if !ok || chunkUploadTargetKey(filepath.Join(directory, parsedTarget)) != targetKey ||
			entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			if os.IsNotExist(infoErr) {
				continue
			}
			return nil, infoErr
		}
		if !info.Mode().IsRegular() {
			continue
		}
		temps = append(temps, chunkUploadTemp{
			path:       filepath.Join(directory, entry.Name()),
			sessionKey: sessionKey,
		})
	}
	return temps, nil
}

// cleanupStaleChunkUploadTemps is called while lockedTarget is already locked.
func cleanupStaleChunkUploadTemps(directory, lockedTarget string) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		logger.Debugf("could not scan chunk upload temporary files in %s: %v", directory, err)
		return
	}

	cutoff := time.Now().Add(-chunkUploadTempTTL)
	lockedTargetKey := chunkUploadTargetKey(lockedTarget)
	for _, entry := range entries {
		targetName, _, ok := parseChunkUploadTempName(directory, entry.Name())
		if !ok || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}

		targetPath := filepath.Join(directory, targetName)
		var unlock func()
		if chunkUploadTargetKey(targetPath) != lockedTargetKey {
			var acquired bool
			unlock, acquired = tryLockChunkUploadTarget(targetPath)
			if !acquired {
				continue
			}
		}

		tempFilePath := filepath.Join(directory, entry.Name())
		info, statErr := os.Lstat(tempFilePath)
		if statErr == nil && info.Mode().IsRegular() && info.ModTime().Before(cutoff) {
			removeChunkUploadTemp(tempFilePath)
		}
		if unlock != nil {
			unlock()
		}
	}
}

func parseChunkUploadTempName(directory, name string) (string, string, bool) {
	tailLength := len(chunkUploadTempMarker) + chunkUploadTempTokenLen + len(chunkUploadTempSuffix)
	if len(name) <= tailLength {
		return "", "", false
	}

	markerStart := len(name) - tailLength
	tokenStart := markerStart + len(chunkUploadTempMarker)
	suffixStart := tokenStart + chunkUploadTempTokenLen
	if name[markerStart:tokenStart] != chunkUploadTempMarker ||
		name[suffixStart:] != chunkUploadTempSuffix {
		return "", "", false
	}

	tokenString := name[tokenStart:suffixStart]
	token, err := base64.RawURLEncoding.DecodeString(tokenString)
	if err != nil || len(token) != chunkUploadSessionKeyBytes+chunkUploadNonceBytes+chunkUploadAuthTagBytes ||
		base64.RawURLEncoding.EncodeToString(token) != tokenString {
		return "", "", false
	}

	sessionKeyBytes := token[:chunkUploadSessionKeyBytes]
	nonce := token[chunkUploadSessionKeyBytes : chunkUploadSessionKeyBytes+chunkUploadNonceBytes]
	authTag := token[chunkUploadSessionKeyBytes+chunkUploadNonceBytes:]
	targetName := name[:markerStart]
	expectedAuthTag, err := chunkUploadAuthenticationTag(filepath.Join(directory, targetName), sessionKeyBytes, nonce)
	if err != nil || !hmac.Equal(authTag, expectedAuthTag) {
		return "", "", false
	}
	return targetName, base64.RawURLEncoding.EncodeToString(sessionKeyBytes), true
}

func removeChunkUploadTemp(tempFilePath string) {
	stopChunkUploadTempCleanup(tempFilePath)
	if err := os.Remove(tempFilePath); err != nil && !os.IsNotExist(err) {
		logger.Debugf("could not remove chunk upload temporary file %s: %v", tempFilePath, err)
	}
}
