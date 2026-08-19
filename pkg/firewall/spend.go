package firewall

import (
	"errors"
	"strings"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/negotiation"
)

// EvaluateSpend judges an action that would commit value.
//
// Two independent things must both hold, and neither substitutes for the
// other. The mandate is what the owner authorised before the conversation
// began, and it bounds the terms. The firewall ceiling is what may happen
// unattended at all, and it bounds the reach of received content. A spend that
// a mandate covers is still stopped if received content drove it past the
// ceiling, and a spend inside the ceiling is still stopped if it is outside
// the mandate. Collapsing the two into one check would let either one alone
// authorise a payment.
func EvaluateSpend(policy Policy, mandate negotiation.Mandate, action Action, now time.Time) (Decision, error) {
	if action.Effect != EffectSpend {
		return Decision{}, errors.New("EvaluateSpend judges a spend")
	}
	decision, err := Evaluate(policy, action)
	if err != nil {
		return Decision{}, err
	}
	// A malformed action is not a policy question, and neither is a set of
	// terms that does not describe a purchase. Neither becomes coherent
	// because an owner said yes.
	if decision.Outcome == Refuse {
		return decision, nil
	}
	if action.Terms == nil {
		decision.Outcome = Refuse
		decision.Reason = "a spend must say what it is buying"
		return decision, nil
	}
	if err := action.Terms.Validate(); err != nil {
		decision.Outcome = Refuse
		decision.Reason = "the terms are not a complete purchase: " + err.Error()
		return decision, nil
	}

	needsApproval, err := mandate.Permits(*action.Terms, now)
	if err != nil {
		// Outside the mandate, or past its expiry. The owner can still say
		// yes; what they cannot do is have said yes in advance.
		decision.Outcome = RequireOwnerApproval
		decision.Reason = "outside what the owner authorised in advance: " + err.Error()
		return decision, nil
	}
	if needsApproval {
		decision.Outcome = RequireOwnerApproval
		decision.Reason = "above the amount the owner chose to decide personally"
		return decision, nil
	}
	return decision, nil
}

// AmountRendering is an exact amount beside the text a message displayed for
// it.
type AmountRendering struct {
	// Structured is the canonical rendering of the amount that would actually
	// be acted on.
	Structured string
	// Rendered is what the message showed a reader.
	Rendered string
	// Agrees reports whether the displayed text contains the exact amount.
	Agrees bool
}

// CheckAmountRendering compares an exact amount against the text that
// accompanied it.
//
// It does not parse the text. Free-form text cannot be parsed reliably, and a
// parser that got it wrong would be choosing an answer, which is the one thing
// this check exists to prevent. The rule is the conservative one: the rendering
// must contain the exact amount, and where it does not, both are returned and
// neither is authoritative. Letting the caller pick the text would make the
// prose authoritative through a side door; letting it silently pick the number
// would hide that the message said something else to the person reading it.
func CheckAmountRendering(amount negotiation.Amount, rendering string) (AmountRendering, error) {
	if err := amount.Validate(); err != nil {
		return AmountRendering{}, err
	}
	if len(rendering) > MaxSummaryBytes {
		return AmountRendering{}, errors.New("rendering exceeds its bound")
	}
	canonical := amount.String()
	return AmountRendering{
		Structured: canonical,
		Rendered:   rendering,
		Agrees:     strings.Contains(rendering, canonical),
	}, nil
}
