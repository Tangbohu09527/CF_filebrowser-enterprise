package audit

import (
	"crypto/sha256"
	"encoding/hex"
)

const (
	tokenRefDomain  = "audit-token-ref:v1\x00"
	shareRefDomain  = "audit-share-ref:v1\x00"
	sourceRefDomain = "audit-source-ref:v1\x00"
)

// DeriveTokenRef returns a stable, domain-separated reference for an existing token hash.
func DeriveTokenRef(tokenHash string) string {
	return deriveReference(tokenRefDomain, tokenHash)
}

// DeriveShareRef returns a stable, domain-separated reference for an existing share hash.
func DeriveShareRef(shareHash string) string {
	return deriveReference(shareRefDomain, shareHash)
}

// DeriveSourceRef returns a stable identifier for a logical source name that cannot be stored verbatim.
func DeriveSourceRef(sourceName string) string {
	reference := deriveReference(sourceRefDomain, sourceName)
	if reference == "" {
		return ""
	}
	return "source." + reference
}

func deriveReference(domain, sourceHash string) string {
	if sourceHash == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(domain + sourceHash))
	return hex.EncodeToString(digest[:])[:32]
}
