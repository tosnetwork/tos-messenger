package main

import (
	"testing"

	"github.com/tosnetwork/tos-messenger/pkg/attachments"
)

func TestInspectText(t *testing.T) {
	cases := []struct {
		name     string
		raw      []byte
		media    string
		decision attachments.ScanDecision
		reason   string
	}{
		{name: "plain", raw: []byte("hello\nworld\t!"), media: "text/plain", decision: attachments.ScanAllow, reason: "utf8_text"},
		{name: "markdown", raw: []byte("# title\n"), media: "text/markdown", decision: attachments.ScanAllow, reason: "utf8_text"},
		{name: "binary nul", raw: []byte{'a', 0, 'b'}, media: "text/plain", decision: attachments.ScanDeny, reason: "invalid_utf8_text"},
		{name: "invalid utf8", raw: []byte{0xff}, media: "text/plain", decision: attachments.ScanDeny, reason: "invalid_utf8_text"},
		{name: "escape control", raw: []byte{'a', 0x1b, 'b'}, media: "text/plain", decision: attachments.ScanDeny, reason: "unsafe_text_control"},
		{name: "carriage return", raw: []byte("a\rb"), media: "text/plain", decision: attachments.ScanDeny, reason: "unsafe_text_control"},
		{name: "unsupported", raw: []byte("hello"), media: "application/pdf", decision: attachments.ScanDeny, reason: "unsupported_media_type"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			decision, reason := inspectText(test.raw, test.media)
			if decision != test.decision || reason != test.reason {
				t.Fatalf("got %s/%s want %s/%s", decision, reason, test.decision, test.reason)
			}
		})
	}
}
