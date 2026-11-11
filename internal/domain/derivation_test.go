package domain

import (
	"crypto/sha256"
	"encoding/json"
	"io"
	"os"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

func TestBrowserDerivationVector(t *testing.T) {
	raw, e := os.ReadFile("../../web/test/vector.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		TrapID, Password, Secret, Hash string
		Policy                         KDFParams
	}
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	salt := sha256.Sum256([]byte("traPortal kdf v1:" + v.TrapID))
	root := argon2.IDKey([]byte(v.Password), salt[:], 3, 65536, 4, 32)
	secret := make([]byte, 32)
	if _, e = io.ReadFull(hkdf.New(sha256.New, root, nil, []byte("traPortal auth v1")), secret); e != nil {
		t.Fatal(e)
	}
	expected, e := DecodeSecret(v.Secret)
	if e != nil {
		t.Fatal(e)
	}
	if string(expected) != string(secret) {
		t.Fatal("Go and browser disagree")
	}
	hash := sha256.Sum256(secret)
	expected, e = DecodeSecret(v.Hash)
	if e != nil || string(hash[:]) != string(expected) {
		t.Fatal("verifier mismatch")
	}
}
