package fault

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// Every code has to be classified. An unclassified code silently becomes
// permanent and invisible, which is a decision nobody made.
func TestEveryCodeIsClassified(t *testing.T) {
	codes := Codes()
	if len(codes) < 20 {
		t.Fatalf("the taxonomy looks truncated: %d codes", len(codes))
	}
	for _, code := range codes {
		if !Known(code) {
			t.Fatalf("%q is not classified", code)
		}
		if code == "" || strings.TrimSpace(string(code)) != string(code) {
			t.Fatalf("malformed code %q", code)
		}
		switch DispositionOf(code) {
		case Permanent, Transient, Refresh, Approval:
		default:
			t.Fatalf("%q has no disposition", code)
		}
	}
}

// The oracle rule: nothing hidden can reach a peer, by any path.
func TestHiddenCodesNeverReachAPeer(t *testing.T) {
	for _, code := range Codes() {
		response := PeerCode(code, 30)
		if PeerVisible(code) {
			if response.Code != code {
				t.Fatalf("visible code %q was replaced by %q", code, response.Code)
			}
			continue
		}
		if response.Code != CodeRejected {
			t.Fatalf("hidden code %q leaked as %q", code, response.Code)
		}
		if response.RetryAfterSeconds != 0 {
			t.Fatalf("hidden code %q leaked a timing hint", code)
		}
		if err := ValidateResponse(Response{Code: code}); err == nil {
			t.Fatalf("hidden code %q passed response validation", code)
		}
	}
}

// Authentication and delivery outcomes are the specific pair an attacker would
// use as a delivery oracle, so they must be indistinguishable from the
// outside.
func TestDeliveryOracleIsClosed(t *testing.T) {
	authentic := PeerCode(CodeNotAuthentic, 0)
	replayed := PeerCode(CodeReplayed, 0)
	approval := PeerCode(CodeApprovalRequired, 0)
	if authentic != replayed || replayed != approval {
		t.Fatalf("refusals are distinguishable: %v %v %v", authentic, replayed, approval)
	}
	if authentic.Code != CodeRejected {
		t.Fatalf("unexpected refusal code %q", authentic.Code)
	}
}

func TestDetailNeverTravels(t *testing.T) {
	secret := "mailbox mbx_deadbeef holds 3 undelivered events"
	response := Peer(New(CodeNotAuthentic, secret), 0)
	encoded, err := EncodeResponseJSON(response)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if strings.Contains(string(encoded), "mbx_") || strings.Contains(string(encoded), secret) {
		t.Fatalf("local detail travelled to a peer: %s", encoded)
	}
}

func TestRetryHintsOnlyWhereTheyMeanSomething(t *testing.T) {
	limited := PeerCode(CodeRateLimited, 42)
	if limited.RetryAfterSeconds != 42 {
		t.Fatalf("a rate limit lost its hint: %+v", limited)
	}
	oversized := PeerCode(CodeOversized, 42)
	if oversized.RetryAfterSeconds != 0 {
		t.Fatal("a permanent refusal carried a retry hint")
	}
	if err := ValidateResponse(Response{Code: CodeOversized, RetryAfterSeconds: 5}); err == nil {
		t.Fatal("a hint on a hintless code was accepted")
	}
	capped := PeerCode(CodeRateLimited, MaxRetryAfterSeconds+1)
	if capped.RetryAfterSeconds != MaxRetryAfterSeconds {
		t.Fatalf("an unbounded hint was accepted: %d", capped.RetryAfterSeconds)
	}
}

func TestRetryDispositions(t *testing.T) {
	permanent := NextCode(CodeOversized, 1)
	if permanent.Allowed || !permanent.Final {
		t.Fatalf("a permanent failure is retryable: %+v", permanent)
	}

	transient := NextCode(CodeUnreachable, 1)
	if !transient.Allowed || transient.After != TransientBase || transient.Final {
		t.Fatalf("unexpected first transient retry: %+v", transient)
	}

	refresh := NextCode(CodeDelegationExpired, 1)
	if !refresh.Allowed || !refresh.ResolveFirst {
		t.Fatalf("a refresh disposition did not ask for current state: %+v", refresh)
	}

	// An approval hold is neither retryable nor final: it resumes on an event.
	approval := NextCode(CodeApprovalRequired, 1)
	if approval.Allowed {
		t.Fatal("an approval hold was put on a timer")
	}
	if approval.Final {
		t.Fatal("an approval hold was treated as unrecoverable")
	}
}

func TestBackoffIsBoundedAndMonotone(t *testing.T) {
	previous := time.Duration(0)
	for attempt := 1; attempt <= TransientAttempts; attempt++ {
		retry := NextCode(CodeUnreachable, attempt)
		if !retry.Allowed {
			t.Fatalf("attempt %d was refused", attempt)
		}
		if retry.After < previous {
			t.Fatalf("backoff went backwards at attempt %d: %v then %v", attempt, previous, retry.After)
		}
		if retry.After > TransientCap {
			t.Fatalf("backoff exceeded its cap at attempt %d: %v", attempt, retry.After)
		}
		previous = retry.After
	}
	if exhausted := NextCode(CodeUnreachable, TransientAttempts+1); !exhausted.Final || exhausted.Allowed {
		t.Fatalf("attempts are unbounded: %+v", exhausted)
	}
	if exhausted := NextCode(CodeDelegationExpired, RefreshAttempts+1); !exhausted.Final {
		t.Fatalf("refresh attempts are unbounded: %+v", exhausted)
	}
	if first := NextCode(CodeUnreachable, 0); first.After != TransientBase {
		t.Fatalf("a nonsense attempt number was not normalised: %+v", first)
	}
}

func TestUnclassifiedFailuresStayInternal(t *testing.T) {
	plain := errors.New("something went wrong in a library")
	if code := CodeOf(plain); code != CodeInternal {
		t.Fatalf("an untyped error became %q", code)
	}
	if response := Peer(plain, 0); response.Code != CodeRejected {
		t.Fatalf("an untyped error leaked as %q", response.Code)
	}
	if retry := Next(plain, 1); !retry.Allowed {
		t.Fatal("an internal failure was treated as permanent")
	}
	if DispositionOf("invented-code") != Permanent {
		t.Fatal("an unknown code was treated as retryable")
	}
}

func TestFaultsMatchByCode(t *testing.T) {
	cause := errors.New("underlying")
	wrapped := Wrap(CodeNotAuthentic, cause)

	if !errors.Is(wrapped, New(CodeNotAuthentic, "")) {
		t.Fatal("faults with the same code did not match")
	}
	if errors.Is(wrapped, New(CodeReplayed, "")) {
		t.Fatal("faults with different codes matched")
	}
	if !errors.Is(wrapped, cause) {
		t.Fatal("the underlying cause was lost")
	}
	extracted, ok := Of(wrapped)
	if !ok || extracted.Code != CodeNotAuthentic {
		t.Fatalf("extraction failed: %+v %v", extracted, ok)
	}
	if !strings.Contains(wrapped.Error(), "underlying") {
		t.Fatalf("local detail was dropped: %s", wrapped.Error())
	}
	if New(CodeInternal, "").Error() != string(CodeInternal) {
		t.Fatal("a detail-free fault rendered unexpectedly")
	}
	var nilFault *Fault
	if nilFault.Error() == "" || nilFault.Unwrap() != nil {
		t.Fatal("a nil fault is not safe to handle")
	}
}

func TestResponseRoundTrip(t *testing.T) {
	response := PeerCode(CodeAdmissionRequired, 600)
	encoded, err := EncodeResponseJSON(response)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeResponseJSON(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded != response {
		t.Fatalf("response changed across transport: %+v vs %+v", decoded, response)
	}
}

func TestDecodeResponseRejectsMalformedTransport(t *testing.T) {
	valid, err := EncodeResponseJSON(PeerCode(CodeRateLimited, 30))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	cases := map[string][]byte{
		"unknown field": []byte(string(valid[:len(valid)-1]) + `,"extra":1}`),
		"trailing json": append(append([]byte{}, valid...), []byte("{}")...),
		"wrong schema":  []byte(strings.Replace(string(valid), ResponseSchema, "other", 1)),
		"unknown code":  []byte(`{"schema":"` + ResponseSchema + `","code":"invented"}`),
		"hidden code":   []byte(`{"schema":"` + ResponseSchema + `","code":"` + string(CodeNotAuthentic) + `"}`),
		"empty":         []byte(""),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeResponseJSON(raw); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
		})
	}
}

// A sender who is refused must be able to act. Codes that describe something
// the sender controls are the ones that have to be visible, or the admission
// model has no remedy.
func TestSenderCorrectableCodesAreVisible(t *testing.T) {
	for _, code := range []Code{
		CodeNetworkMismatch, CodeDelegationUncommitted, CodeDelegationExpired,
		CodeSignatureInvalid, CodeClassNotDelegated, CodeAdmissionRequired,
		CodeUnknownEventKind, CodeContentTooLarge, CodeOversized, CodeSuiteUnsupported,
		CodeSenderMismatch, CodeEventOutsideWindow,
	} {
		if !PeerVisible(code) {
			t.Fatalf("%q is something the sender must be able to fix", code)
		}
	}
}
