package attachmentcorpus

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
)

func TestSignedManifestAndReportRoundTrip(t *testing.T) {
	approver := testKey(1)
	runner := testKey(2)
	manifest, err := SignManifest(testManifest(), approver)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest(manifest, approver.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeManifestJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeManifestJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest(decoded, approver.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}

	report, err := SignReport(testReport(SHA256Hex(raw)), runner)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReport(report, manifest, SHA256Hex(raw), strings.Repeat("9", 64), runner.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	reportRaw, err := EncodeReportJSON(report)
	if err != nil {
		t.Fatal(err)
	}
	decodedReport, err := DecodeReportJSON(reportRaw)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReport(decodedReport, manifest, SHA256Hex(raw), strings.Repeat("9", 64), runner.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
}

func TestManifestRefusesSubstitutionAndAmbiguousJSON(t *testing.T) {
	approver := testKey(3)
	other := testKey(4)
	manifest, err := SignManifest(testManifest(), approver)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Manifest){
		"sample digest": func(value *Manifest) { value.Samples[0].SHA256 = strings.Repeat("a", 64) },
		"sample order":  func(value *Manifest) { value.Samples[0], value.Samples[1] = value.Samples[1], value.Samples[0] },
		"scope":         func(value *Manifest) { value.Scope = "another scope" },
		"signature":     func(value *Manifest) { value.SignatureHex = strings.Repeat("0", 128) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := manifest
			changed.Samples = append([]Sample(nil), manifest.Samples...)
			mutate(&changed)
			if err := VerifyManifest(changed, approver.Public().(ed25519.PublicKey)); err == nil {
				t.Fatal("mutated corpus manifest verified")
			}
		})
	}
	if err := VerifyManifest(manifest, other.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("corpus manifest verified for another approver")
	}
	raw, err := EncodeManifestJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeManifestJSON(append(raw, []byte(`{"extra":true}`)...)); err == nil {
		t.Fatal("trailing corpus JSON accepted")
	}
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	object["unknown"] = true
	unknown, _ := json.Marshal(object)
	if _, err := DecodeManifestJSON(unknown); err == nil {
		t.Fatal("unknown corpus field accepted")
	}
}

func TestUnsignedManifestDraftCannotChooseApprovalAuthority(t *testing.T) {
	draft := testManifest()
	draft.ApproverPublicKeyHex = ""
	draft.SignatureHex = ""
	raw, err := json.Marshal(draft)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeManifestDraftJSON(raw)
	if err != nil || decoded.CorpusID != draft.CorpusID {
		t.Fatalf("decode manifest draft: %+v err=%v", decoded, err)
	}
	draft.ApproverPublicKeyHex = strings.Repeat("1", 64)
	raw, _ = json.Marshal(draft)
	if _, err := DecodeManifestDraftJSON(raw); err == nil {
		t.Fatal("draft-chosen approver key accepted")
	}
}

func TestReportRefusesFalseSuccessAndIdentitySubstitution(t *testing.T) {
	runner := testKey(5)
	report, err := SignReport(testReport(strings.Repeat("8", 64)), runner)
	if err != nil {
		t.Fatal(err)
	}
	public := runner.Public().(ed25519.PublicKey)
	manifest := testManifest()
	if err := VerifyReport(report, manifest, strings.Repeat("8", 64), strings.Repeat("9", 64), public); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Report){
		"observed mismatch": func(value *Report) { value.Results[1].ObservedDecision = DecisionAllow },
		"scanner digest":    func(value *Report) { value.Results[0].ScannerDigest = "sha256:" + strings.Repeat("a", 64) },
		"resource":          func(value *Report) { value.Results[0].Resources[0].Name = "z.cvd" },
		"signature":         func(value *Report) { value.SignatureHex = strings.Repeat("0", 128) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := report
			changed.Results = cloneResults(report.Results)
			mutate(&changed)
			if err := VerifyReport(changed, manifest, strings.Repeat("8", 64), strings.Repeat("9", 64), public); err == nil {
				t.Fatal("mutated corpus report verified")
			}
		})
	}
	if err := VerifyReport(report, manifest, strings.Repeat("7", 64), strings.Repeat("9", 64), public); err == nil {
		t.Fatal("report verified against another manifest")
	}
	if err := VerifyReport(report, manifest, strings.Repeat("8", 64), strings.Repeat("7", 64), public); err == nil {
		t.Fatal("report verified against another policy")
	}
}

func testManifest() Manifest {
	return Manifest{
		Schema: ManifestSchema, CorpusID: "external-review-2026", Revision: "r1", ApprovedAtUnix: 1_800_000_000,
		Scope: "Private release corpus selected by an external malware reviewer.",
		Samples: []Sample{
			{Name: "clean-control.txt", SHA256: strings.Repeat("1", 64), SizeBytes: 19,
				Category: "clean-control", MediaType: "text/plain", ExpectedDecision: DecisionAllow},
			{Name: "hostile-control.bin", SHA256: strings.Repeat("2", 64), SizeBytes: 37,
				Category: "malware-control", MediaType: "text/plain", ExpectedDecision: DecisionDeny},
		},
	}
}

func testReport(manifestDigest string) Report {
	resources := []ResourceEvidence{{Name: "clamav.crt", Digest: "sha256:" + strings.Repeat("3", 64)},
		{Name: "clamscan", Digest: "sha256:" + strings.Repeat("4", 64)}}
	return Report{Schema: ReportSchema, ManifestSHA256: manifestDigest,
		AdmissionPolicySHA256: strings.Repeat("9", 64), RunnerCommit: strings.Repeat("a", 40),
		Toolchain: "go1.test linux/amd64", RunAtUnix: 1_800_000_100,
		Results: []Result{
			{Name: "clean-control.txt", SHA256: strings.Repeat("1", 64), ExpectedDecision: DecisionAllow,
				ObservedDecision: DecisionAllow, ScannerID: "clamav-official", ScannerDigest: "sha256:" + strings.Repeat("5", 64), ReasonCode: "clean", Resources: resources},
			{Name: "hostile-control.bin", SHA256: strings.Repeat("2", 64), ExpectedDecision: DecisionDeny,
				ObservedDecision: DecisionDeny, ScannerID: "clamav-official", ScannerDigest: "sha256:" + strings.Repeat("5", 64), ReasonCode: "infected", Resources: resources},
		}}
}

func testKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytesOf(seed, ed25519.SeedSize))
}

func bytesOf(value byte, length int) []byte {
	result := make([]byte, length)
	for index := range result {
		result[index] = value
	}
	return result
}

func cloneResults(values []Result) []Result {
	result := append([]Result(nil), values...)
	for index := range result {
		result[index].Resources = append([]ResourceEvidence(nil), values[index].Resources...)
	}
	return result
}
