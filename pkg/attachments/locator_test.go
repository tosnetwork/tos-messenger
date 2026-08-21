package attachments

import (
	"strings"
	"testing"
)

func TestHTTPSLocatorIsExactAndNonBearer(t *testing.T) {
	digest := "sha256:" + strings.Repeat("ab", 32)
	want := "https://attachments.example/.well-known/tos-messenger/attachments/" + strings.Repeat("ab", 32)
	locator, err := HTTPSLocator("https://attachments.example", digest)
	if err != nil || locator != want {
		t.Fatalf("locator=%q err=%v", locator, err)
	}
	if parsed, err := ParseHTTPSLocator(locator, digest); err != nil || parsed.Path == "" {
		t.Fatalf("parsed=%v err=%v", parsed, err)
	}
	for _, candidate := range []string{
		"http://attachments.example/.well-known/tos-messenger/attachments/" + strings.Repeat("ab", 32),
		"https://user@attachments.example/.well-known/tos-messenger/attachments/" + strings.Repeat("ab", 32),
		"https://ATTACHMENTS.example/.well-known/tos-messenger/attachments/" + strings.Repeat("ab", 32),
		"https://attachments/.well-known/tos-messenger/attachments/" + strings.Repeat("ab", 32),
		"https://attächments.example/.well-known/tos-messenger/attachments/" + strings.Repeat("ab", 32),
		"https://-attachments.example/.well-known/tos-messenger/attachments/" + strings.Repeat("ab", 32),
		"https://127.0.0.01/.well-known/tos-messenger/attachments/" + strings.Repeat("ab", 32),
		"https://attachments.example:443/.well-known/tos-messenger/attachments/" + strings.Repeat("ab", 32),
		want + "?token=bearer",
		want + "#fragment",
		want + "/extra",
		"https://attachments.example/.well-known/tos-messenger/attachments/" + strings.Repeat("cd", 32),
	} {
		if _, err := ParseHTTPSLocator(candidate, digest); err == nil {
			t.Fatalf("accepted %q", candidate)
		}
	}
	for _, origin := range []string{"https://attachments.example/path", "https://attachments.example:443", "https://ATTACHMENTS.example", "https://attachments"} {
		if _, err := HTTPSLocator(origin, digest); err == nil {
			t.Fatalf("accepted origin %q", origin)
		}
	}
}
