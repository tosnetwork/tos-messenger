package room

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/identity"
)

func signedRolePolicy(t *testing.T) (Membership, RolePolicy, identityFixture) {
	t.Helper()
	authorityAgent := agent(1)
	moderatorAgent := agent(2)
	memberAgent := agent(3)
	membership := mustFound(t, authorityAgent, moderatorAgent, memberAgent)
	delegation, key := authorityDelegation(t, authorityAgent, 0x51)
	policy, err := SignRolePolicy(RolePolicy{
		Network: delegation.Network, RoomID: membership.RoomID, MembershipEpoch: membership.Epoch,
		MembershipDigest: membership.Digest, Revision: 1,
		Assignments:  []RoleAssignment{{AgentID: authorityAgent, Role: RoleAdministrator}, {AgentID: moderatorAgent, Role: RoleModerator}},
		Authority:    Authority{AgentID: authorityAgent, EndpointID: delegation.EndpointID},
		IssuedAtUnix: 200, ExpiresAtUnix: 300,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return membership, policy, identityFixture{delegation: delegation}
}

type identityFixture struct{ delegation identity.Delegation }

func TestRolePolicyBindsMembershipAndBoundsPowers(t *testing.T) {
	membership, policy, fixture := signedRolePolicy(t)
	if err := VerifyRolePolicy(policy, membership, policy.Authority, fixture.delegation, time.Unix(250, 0)); err != nil {
		t.Fatalf("verify: %v", err)
	}
	admin, moderator, member := membership.Members[0], membership.Members[1], membership.Members[2]
	if !policy.Allows(membership, admin, ActionChangeMembership) || !policy.Allows(membership, admin, ActionModerate) {
		t.Fatal("administrator did not receive bounded administrative powers")
	}
	if !policy.Allows(membership, moderator, ActionModerate) || policy.Allows(membership, moderator, ActionChangeRoles) {
		t.Fatal("moderator powers were widened or omitted")
	}
	if !policy.Allows(membership, member, ActionPost) || policy.Allows(membership, member, ActionModerate) {
		t.Fatal("ordinary member powers were widened or omitted")
	}
	outsider := agent(9)
	if policy.Allows(membership, outsider, ActionPost) || policy.Allows(membership, admin, Action("unknown")) {
		t.Fatal("unknown principal or action was admitted")
	}

	next, err := membership.Add([]string{agent(4)})
	if err != nil {
		t.Fatal(err)
	}
	if policy.Allows(next, admin, ActionChangeMembership) {
		t.Fatal("old role policy survived a membership transition")
	}
	if err := VerifyRolePolicy(policy, next, policy.Authority, fixture.delegation, time.Unix(250, 0)); err == nil {
		t.Fatal("old role policy verified against a successor membership")
	}
}

func TestRolePolicyRejectsSubstitutionAndExcessPower(t *testing.T) {
	membership, policy, fixture := signedRolePolicy(t)
	now := time.Unix(250, 0)
	cases := map[string]func(*RolePolicy){
		"wrong digest":    func(p *RolePolicy) { p.MembershipDigest = "sha256:" + strings.Repeat("9", 64) },
		"wrong authority": func(p *RolePolicy) { p.Authority.AgentID = agent(2) },
		"non-member":      func(p *RolePolicy) { p.Assignments[1].AgentID = agent(9) },
		"expired":         func(p *RolePolicy) { p.ExpiresAtUnix = 249 },
		"bad signature":   func(p *RolePolicy) { p.EndpointSignature[0] ^= 1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := policy
			candidate.Assignments = append([]RoleAssignment(nil), policy.Assignments...)
			candidate.EndpointSignature = append([]byte(nil), policy.EndpointSignature...)
			mutate(&candidate)
			if err := VerifyRolePolicy(candidate, membership, policy.Authority, fixture.delegation, now); err == nil {
				t.Fatal("substituted policy verified")
			}
		})
	}

	excess := policy
	excess.EndpointSignature = nil
	excess.Assignments = make([]RoleAssignment, 0, MaxRoomAdmins+1)
	for index := 0; index < MaxRoomAdmins+1; index++ {
		excess.Assignments = append(excess.Assignments, RoleAssignment{AgentID: agent(byte(index + 1)), Role: RoleAdministrator})
	}
	if _, err := SignRolePolicy(excess, bytes.Repeat([]byte{1}, 64)); err == nil {
		t.Fatal("administrator ceiling was not enforced")
	}
}

func TestRolePolicyStrictWireRoundTrip(t *testing.T) {
	membership, policy, fixture := signedRolePolicy(t)
	raw, err := EncodeRolePolicyJSON(policy)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRolePolicyJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRolePolicy(decoded, membership, policy.Authority, fixture.delegation, time.Unix(250, 0)); err != nil {
		t.Fatalf("round trip: %v", err)
	}

	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	object["unexpected"] = true
	unknown, _ := json.Marshal(object)
	if _, err := DecodeRolePolicyJSON(unknown); err == nil {
		t.Fatal("unknown field was accepted")
	}
	if _, err := DecodeRolePolicyJSON(append(raw, []byte(" {}")...)); err == nil {
		t.Fatal("trailing JSON was accepted")
	}

	object = map[string]any{}
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	object["endpoint_signature_base64"] = "not canonical=="
	badEncoding, _ := json.Marshal(object)
	if _, err := DecodeRolePolicyJSON(badEncoding); err == nil {
		t.Fatal("non-canonical signature encoding was accepted")
	}
}
