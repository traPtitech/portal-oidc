package v1

import "testing"

func TestSanitizeReturnURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", "/"},
		{"root", "/", "/"},
		{"path", "/oauth2/authorize", "/oauth2/authorize"},
		{"path with query", "/oauth2/authorize?foo=bar", "/oauth2/authorize?foo=bar"},
		{"protocol relative", "//evil.com/x", "/"},
		{"absolute http", "http://evil.com/x", "/"},
		{"absolute https", "https://evil.com/x", "/"},
		{"javascript scheme", "javascript:alert(1)", "/"},
		{"backslash", "/\\evil.com", "/"},
		{"bare relative", "foo", "/"},
		{"opaque", "mailto:a@b.c", "/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeReturnURL(tc.in)
			if got != tc.want {
				t.Errorf("sanitizeReturnURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
