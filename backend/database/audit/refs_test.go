package audit

import (
	"regexp"
	"testing"
)

func TestSecureReferences(t *testing.T) {
	const inputHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	tokenRef := DeriveTokenRef(inputHash)
	shareRef := DeriveShareRef(inputHash)
	sourceRef := DeriveSourceRef(inputHash)
	if tokenRef != "d718c2de78ab46d6ed87af1d011135c0" {
		t.Fatalf("token reference: got %q", tokenRef)
	}
	if shareRef != "6e4a27d3584675cc8dc740278af513fb" {
		t.Fatalf("share reference: got %q", shareRef)
	}
	if tokenRef == shareRef {
		t.Fatal("token and share reference domains must be isolated")
	}
	if sourceRef == "source."+tokenRef || sourceRef == "source."+shareRef {
		t.Fatal("source reference domain must be isolated")
	}
	if !regexp.MustCompile(`^source\.[0-9a-f]{32}$`).MatchString(sourceRef) {
		t.Fatalf("source reference: got %q", sourceRef)
	}
	if sourceRef != DeriveSourceRef(inputHash) || sourceRef == "source."+inputHash[:32] {
		t.Fatal("source reference must be stable without exposing the source prefix")
	}
	if tokenRef != DeriveTokenRef(inputHash) || shareRef != DeriveShareRef(inputHash) {
		t.Fatal("references must be stable")
	}
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(tokenRef) ||
		!regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(shareRef) {
		t.Fatal("references must be 32 lowercase hexadecimal characters")
	}
	if tokenRef == inputHash || tokenRef == inputHash[:32] ||
		shareRef == inputHash || shareRef == inputHash[:32] {
		t.Fatal("references must not expose the source hash or its prefix")
	}
	if tokenRef == DeriveTokenRef("different-hash") || shareRef == DeriveShareRef("different-hash") {
		t.Fatal("different inputs must not produce the same test reference")
	}
}

func TestSecureReferencesEmptyInput(t *testing.T) {
	if got := DeriveTokenRef(""); got != "" {
		t.Fatalf("empty token hash: got %q", got)
	}
	if got := DeriveShareRef(""); got != "" {
		t.Fatalf("empty share hash: got %q", got)
	}
	if got := DeriveSourceRef(""); got != "" {
		t.Fatalf("empty source name: got %q", got)
	}
}
