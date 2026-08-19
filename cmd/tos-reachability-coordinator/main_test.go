package main

import (
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/probe"
)

func TestRunRefusesUnusableConfiguration(t *testing.T) {
	cases := map[string]struct {
		listen      string
		serverID    string
		ttl         time.Duration
		maxSessions int
		perWindow   int
		window      time.Duration
	}{
		"bad server id":   {"127.0.0.1:0", "srv_bad", probe.DefaultSessionTTL, 1, 1, time.Minute},
		"negative ttl":    {"127.0.0.1:0", "", -time.Second, 1, 1, time.Minute},
		"negative window": {"127.0.0.1:0", "", probe.DefaultSessionTTL, 1, 1, -time.Minute},
		"bad listener":    {"not an address", "", probe.DefaultSessionTTL, 1, 1, time.Minute},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			err := run(testCase.listen, testCase.serverID, testCase.ttl,
				testCase.maxSessions, testCase.perWindow, testCase.window)
			if err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
		})
	}
}
