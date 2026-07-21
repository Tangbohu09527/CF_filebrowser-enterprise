package utils

import (
	"os"
	"unicode/utf8"
)

// IsTextFile checks if a file is viewable/editable as text (like with cat or a text editor).
// It returns true if the file appears to be text, false if it's likely binary.
// This function uses simple heuristics:
// - Valid UTF-8 encoding
// - Not full of null bytes (which indicate binary data)
func IsTextFile(realPath string) (bool, error) {
	content, err := os.ReadFile(realPath)
	if err != nil {
		return false, err
	}
	return IsTextContent(content), nil
}

// IsTextContent applies the same text heuristics as IsTextFile to bytes already
// read from an authorized file descriptor.
func IsTextContent(content []byte) bool {
	const sampleSize = 8192
	const maxNullByteRatio = 0.05
	// Empty files are considered text
	if len(content) == 0 {
		return true
	}
	// Use sample for large files to avoid reading entire file into memory
	sample := content
	if len(content) > sampleSize {
		sample = content[:sampleSize]
	}
	// Check 1: Count null bytes - binary files typically have many nulls
	nullCount := 0
	for _, b := range sample {
		if b == 0x00 {
			nullCount++
		}
	}

	if nullCount > 0 {
		nullRatio := float64(nullCount) / float64(len(sample))
		if nullRatio > maxNullByteRatio {
			return false
		}
	}

	// Check 2: Validate UTF-8 encoding
	// Trim sample to last complete UTF-8 rune to avoid false negatives
	trimmedSample := sample
	for len(trimmedSample) > 0 {
		lastRune, size := utf8.DecodeLastRune(trimmedSample)
		if lastRune != utf8.RuneError {
			break
		}
		if size == 1 {
			trimmedSample = trimmedSample[:len(trimmedSample)-1]
		} else {
			break
		}
	}

	if len(trimmedSample) > 0 && !utf8.Valid(trimmedSample) {
		return false
	}

	return true
}
