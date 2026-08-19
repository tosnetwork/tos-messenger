package eventlog

import (
	"strings"
	"testing"
	"time"
)

func testMandate() StoredMandate {
	return StoredMandate{
		Objective: "buy transcription", Authority: "commit",
		CapabilityClass: "transcription.audio",
		MaxTotalAsset:   "TOS", MaxTotalUnits: 1000, MaxTotalDecimals: 2,
		ApprovalAsset: "TOS", ApprovalUnits: 500, ApprovalDecimals: 2,
		MaxCounteroffers: 4, ExpiresAtUnix: 1_800_086_400,
	}
}

// A mandate a runtime names must be the authorisation the owner placed, not a
// handle that could be pointed at something else later.
func TestMandateIdentifierCommitsItsTerms(t *testing.T) {
	first, err := MandateID(testMandate())
	if err != nil {
		t.Fatalf("identify: %v", err)
	}
	larger := testMandate()
	larger.MaxTotalUnits = 9000
	second, err := MandateID(larger)
	if err != nil {
		t.Fatalf("identify: %v", err)
	}
	if first == second {
		t.Fatal("two different ceilings shared one mandate identifier")
	}
	if _, err := MandateID(StoredMandate{}); err == nil {
		t.Fatal("an empty mandate was given an identifier")
	}
}

func TestMandateIsPlacedReadAndWithdrawn(t *testing.T) {
	journal := approvalJournal(t)
	now := time.Unix(1_800_000_060, 0)

	placed, err := journal.PlaceMandate(testMandate(), now)
	if err != nil {
		t.Fatalf("place: %v", err)
	}
	if placed.MandateID == "" || placed.PlacedAtUnix == 0 {
		t.Fatalf("the mandate was not recorded: %+v", placed)
	}
	if !placed.Live(now) {
		t.Fatal("a freshly placed mandate was not live")
	}

	held, err := journal.ListMandates()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(held) != 1 || held[0].Objective != "buy transcription" {
		t.Fatalf("the owner could not read back what they authorised: %+v", held)
	}

	withdrawn, err := journal.RevokeMandate(placed.MandateID, now)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if withdrawn.RevokedAtUnix == 0 || withdrawn.Live(now) {
		t.Fatalf("the withdrawal was not recorded: %+v", withdrawn)
	}
	// The record survives the withdrawal: an owner asking what was allowed
	// last week needs the answer to still exist.
	if held, err := journal.ListMandates(); err != nil {
		t.Fatalf("list: %v", err)
	} else if len(held) != 1 {
		t.Fatalf("a withdrawn mandate was deleted: %+v", held)
	}

	// Asking again does not bring it back: the identifier is derived from the
	// terms, so the same request is the same withdrawn authorisation.
	again, err := journal.PlaceMandate(testMandate(), now)
	if err != nil {
		t.Fatalf("place: %v", err)
	}
	if again.RevokedAtUnix == 0 {
		t.Fatal("placing the same mandate again reopened a withdrawn one")
	}
}

// An expiry that has passed is not a smaller mandate.
func TestExpiredMandateIsNotLive(t *testing.T) {
	mandate := testMandate()
	if mandate.Live(time.Unix(int64(mandate.ExpiresAtUnix)+1, 0)) {
		t.Fatal("an expired mandate was still live")
	}
}

func TestMandateInputsAreValidated(t *testing.T) {
	journal := approvalJournal(t)
	now := time.Unix(1_800_000_060, 0)
	cases := map[string]func(*StoredMandate){
		"no objective": func(m *StoredMandate) { m.Objective = "" },
		"no authority": func(m *StoredMandate) { m.Authority = "" },
		"no class":     func(m *StoredMandate) { m.CapabilityClass = "" },
		"no asset":     func(m *StoredMandate) { m.MaxTotalAsset = "" },
		"no expiry":    func(m *StoredMandate) { m.ExpiresAtUnix = 0 },
		"long objective": func(m *StoredMandate) {
			m.Objective = strings.Repeat("x", MaxApprovalSummaryBytes+1)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			mandate := testMandate()
			mutate(&mandate)
			if _, err := journal.PlaceMandate(mandate, now); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
		})
	}
	if _, err := journal.RevokeMandate("mdt_"+strings.Repeat("f", 64), now); err == nil {
		t.Fatal("a mandate nobody placed was withdrawn")
	}
	if _, _, err := journal.LookupMandate("nonsense"); err == nil {
		t.Fatal("an invalid mandate identifier was looked up")
	}
}
