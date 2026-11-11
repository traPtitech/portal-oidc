package domain

import (
	"encoding/base64"
	"testing"
)

func TestVerifierRejectsNonCanonicalEncoding(t *testing.T) {
	good := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, v := range []string{good + "=", good + "\n", good[:42], "!" + good[1:], base64.RawURLEncoding.EncodeToString(make([]byte, 31))} {
		if _, e := DecodeSecret(v); e == nil {
			t.Fatal("accepted invalid encoding")
		}
	}
	if _, e := DecodeSecret(good); e != nil {
		t.Fatal(e)
	}
}
