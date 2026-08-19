package ids

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

// Every identifier kind must reject every other kind's values. If two patterns
// overlap, a value of one kind can be presented where another is expected, and
// every check that follows is looking at the wrong object.
func TestKindsDoNotOverlap(t *testing.T) {
	body := strings.Repeat("a", 64)
	values := map[string]string{
		"agent_": "agent_" + body, "cap_": "cap_" + body, "mep_": "mep_" + body,
		"dev_": "dev_" + body, "conv_": "conv_" + body, "evt_": "evt_" + body,
		"room_": "room_" + body, "thr_": "thr_" + body, "mbx_": "mbx_" + body,
		"msg_": "msg_" + body, "adnl:": "adnl:" + body,
	}
	patterns := map[string]*regexp.Regexp{
		"agent_": Agent, "cap_": Capability, "mep_": Endpoint, "dev_": Device,
		"conv_": Conversation, "evt_": Event, "room_": Room, "thr_": Thread,
		"mbx_": Mailbox, "msg_": RelayMessage, "adnl:": ADNL,
	}
	if len(values) != len(patterns) {
		t.Fatalf("every kind needs a sample: %d values, %d patterns", len(values), len(patterns))
	}
	for owner, pattern := range patterns {
		if !pattern.MatchString(values[owner]) {
			t.Fatalf("%s does not match its own value", owner)
		}
		for kind, value := range values {
			if kind == owner {
				continue
			}
			if pattern.MatchString(value) {
				t.Fatalf("%s matched a %s identifier", owner, kind)
			}
		}
	}
}

func TestPatternsRejectMalformedValues(t *testing.T) {
	for _, invalid := range []string{
		"", "agent_", "agent_" + strings.Repeat("a", 63), "agent_" + strings.Repeat("a", 65),
		"agent_" + strings.Repeat("A", 64), "agent_" + strings.Repeat("z", 64),
		" agent_" + strings.Repeat("a", 64), "agent_" + strings.Repeat("a", 64) + " ",
	} {
		if Agent.MatchString(invalid) {
			t.Fatalf("expected %q to be refused", invalid)
		}
	}
}

func TestFormatRefusesWeakMaterial(t *testing.T) {
	raw := bytes.Repeat([]byte{0x5a}, 32)
	formatted, err := Format("dev_", raw)
	if err != nil {
		t.Fatalf("format: %v", err)
	}
	if !Device.MatchString(formatted) {
		t.Fatalf("unexpected identifier: %s", formatted)
	}
	for name, material := range map[string][]byte{
		"short": bytes.Repeat([]byte{1}, 31),
		"long":  bytes.Repeat([]byte{1}, 33),
		"zero":  make([]byte, 32),
		"empty": nil,
	} {
		if _, err := Format("dev_", material); err == nil {
			t.Fatalf("expected %s material to be refused", name)
		}
	}
	if _, err := Format("", raw); err == nil {
		t.Fatal("expected an empty prefix to be refused")
	}
}
