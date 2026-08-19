package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestSplitAddresses(t *testing.T) {
	got := splitAddresses(" host-1:7691 , host-2:7691 ,, ")
	if len(got) != 2 || got[0] != "host-1:7691" || got[1] != "host-2:7691" {
		t.Fatalf("unexpected addresses: %v", got)
	}
	if len(splitAddresses("   ")) != 0 {
		t.Fatal("expected no addresses from blank input")
	}
}

func TestMeasureRefusesUnusableInput(t *testing.T) {
	ctx := context.Background()
	labels := declared{operator: "lab", carrier: "consumer-isp", udpPolicy: "allowed",
		mobility: "stationary", class: "desktop", assistance: "none"}
	commit := strings.Repeat("a", 40)
	session := "ses_0123456789abcdef0123456789abcdef"

	if _, err := measure(ctx, "", session, "a", ":0", commit, time.Second, time.Second, labels); err == nil {
		t.Fatal("expected a missing coordinator to be refused")
	}
	blank := labels
	blank.operator = ""
	if _, err := measure(ctx, "127.0.0.1:1", session, "a", ":0", commit, time.Second, time.Second, blank); err == nil {
		t.Fatal("expected a missing operator to be refused")
	}
	if _, err := measure(ctx, "127.0.0.1:1", "ses_short", "a", ":0", commit, time.Second, time.Second, labels); err == nil {
		t.Fatal("expected an invalid session to be refused")
	}
	if _, err := measure(ctx, "127.0.0.1:1", session, "c", ":0", commit, time.Second, time.Second, labels); err == nil {
		t.Fatal("expected an invalid role to be refused")
	}
}

// A probe that never reached a coordinator has no stratum to file its result
// under, so it must refuse to write a record rather than invent labels.
func TestMeasureRefusesToRecordAnUnclassifiedTrial(t *testing.T) {
	labels := declared{operator: "lab", carrier: "consumer-isp", udpPolicy: "allowed",
		mobility: "stationary", class: "desktop", assistance: "none"}
	_, err := measure(context.Background(), "127.0.0.1:9",
		"ses_0123456789abcdef0123456789abcdef", "a", "127.0.0.1:0",
		strings.Repeat("a", 40), 200*time.Millisecond, 200*time.Millisecond, labels)
	if err == nil {
		t.Fatal("expected an unclassified trial to be refused")
	}
	if !strings.Contains(err.Error(), "commit") && !strings.Contains(err.Error(), "reachability") {
		t.Fatalf("unexpected refusal reason: %v", err)
	}
}
