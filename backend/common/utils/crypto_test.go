package utils

import (
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestGenerateKeySurvivesJSONPersistence(t *testing.T) {
	key := GenerateKey()
	decoded, decodeErr := hex.DecodeString(key)
	if decodeErr != nil || len(decoded) != 64 {
		t.Fatal("generated signing key must encode 64 random bytes as hex")
	}
	encoded, marshalErr := json.Marshal(key)
	if marshalErr != nil {
		t.Fatal("generated signing key could not be encoded for persistence")
	}
	var restored string
	if unmarshalErr := json.Unmarshal(encoded, &restored); unmarshalErr != nil {
		t.Fatal("persisted signing key could not be decoded")
	}
	if restored != key {
		t.Fatal("JSON persistence changed the generated signing key")
	}
}
