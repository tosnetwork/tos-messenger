package main

import "testing"

func TestOptionsRequireOneExactOperationShape(t *testing.T) {
	assemble := options{mode: "assemble", config: "/config", policy: "/policy",
		firstDescriptor: "/first-descriptor", firstSet: "/first-set",
		secondDescriptor: "/second-descriptor", secondSet: "/second-set"}
	verify := options{mode: "verify", config: "/config", policy: "/policy", evidence: "/evidence"}
	if err := assemble.validate(); err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if err := verify.validate(); err != nil {
		t.Fatalf("verify: %v", err)
	}

	for name, candidate := range map[string]options{
		"unknown mode":      {mode: "trust", config: "/config", policy: "/policy"},
		"missing authority": {mode: "verify", evidence: "/evidence"},
		"missing pair":      {mode: "assemble", config: "/config", policy: "/policy", firstDescriptor: "/first"},
		"mixed operations":  {mode: "verify", config: "/config", policy: "/policy", evidence: "/evidence", firstSet: "/set"},
		"assemble with input": {mode: "assemble", config: "/config", policy: "/policy", evidence: "/evidence",
			firstDescriptor: "/first-descriptor", firstSet: "/first-set", secondDescriptor: "/second-descriptor", secondSet: "/second-set"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := candidate.validate(); err == nil {
				t.Fatal("ambiguous command shape was accepted")
			}
		})
	}
}
