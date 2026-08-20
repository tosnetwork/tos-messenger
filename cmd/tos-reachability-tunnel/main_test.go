package main

import (
	"testing"
	"time"
)

// The daemon refuses to start on limits it cannot honour, for the same reason
// the relay itself does: a measurement service that quietly substituted its
// own limits would make the resulting matrix unreproducible.
func TestRunRefusesUnusableConfiguration(t *testing.T) {
	if err := run("127.0.0.1:0", -time.Second, 1, 1, 1, time.Second); err == nil {
		t.Fatal("a negative session lifetime was accepted")
	}
	if err := run("127.0.0.1:0", time.Second, -1, 1, 1, time.Second); err == nil {
		t.Fatal("a negative session capacity was accepted")
	}
	if err := run("not a listen address", time.Second, 1, 1, 1, time.Second); err == nil {
		t.Fatal("an unusable listen address was accepted")
	}
}
