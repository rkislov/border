package mschap

import (
	"encoding/hex"
	"testing"
)

func TestRFC3079Keys(t *testing.T) {
	hh, _ := hex.DecodeString("41C00C584BD2D91C4017A2A12FA59F3F")
	response, _ := hex.DecodeString("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF")
	key := SessionKey(hh, response)
	if len(key) != 32 || hex.EncodeToString(key[16:]) != "8b7cdc149b993a1ba118cb153f56dccb" {
		t.Fatalf("RFC3079 server send key mismatch: %x", key)
	}
	if SessionKey(nil, response) != nil {
		t.Fatal("invalid secret accepted")
	}
}
