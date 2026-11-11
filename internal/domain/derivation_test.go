package domain

import (
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/json"
	"os"
	"testing"
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
	if v.Policy != CurrentKDFPolicy() {
		t.Fatal("vector policy differs from the current policy")
	}
	salt := sha256.Sum256([]byte("traPortal kdf v1:" + v.TrapID))
	root, e := pbkdf2.Key(sha256.New, v.Password, salt[:], v.Policy.Iterations, 32)
	if e != nil {
		t.Fatal(e)
	}
	secret, e := hkdf.Key(sha256.New, root, nil, "traPortal auth v1", 32)
	if e != nil {
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
