// Package negotiation is the layer between what an Agent says and what the
// system may do.
//
// Natural language is where meaning is communicated. It is not where money
// moves, tools are granted, quotes are accepted, escrow is released, or
// physical action is authorised. Everything in this package exists to keep
// that line where it is: an intent is compiled into typed terms, the typed
// terms are checked against a mandate the owner set beforehand, and agreement
// in conversation remains agreement in conversation until a canonical Quote
// says otherwise.
//
// Nothing here creates, accepts, or funds anything. It decides whether a
// proposed action is inside what the owner already permitted, and produces the
// exact terms a commitment would have to match.
package negotiation

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// MaxDecimals bounds an asset's precision. It is well beyond any real asset
// and exists so a malformed value cannot make arithmetic meaningless.
const MaxDecimals = 30

var assetPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]{1,15}$`)

// Amount is an exact quantity of one asset.
//
// It is integer units and a decimal exponent, never a float. A price compared,
// summed, or rounded in floating point is a price that can differ between two
// implementations that both believe they agreed, and the whole point of this
// layer is that two parties can check they mean the same number.
type Amount struct {
	Asset    string `json:"asset"`
	Units    uint64 `json:"units"`
	Decimals uint8  `json:"decimals"`
}

// Validate enforces a usable amount.
func (a Amount) Validate() error {
	if !assetPattern.MatchString(a.Asset) {
		return errors.New("invalid asset")
	}
	if a.Decimals > MaxDecimals {
		return errors.New("asset precision exceeds its bound")
	}
	return nil
}

// SameAsset reports whether two amounts are even comparable.
func (a Amount) SameAsset(other Amount) bool {
	return a.Asset == other.Asset && a.Decimals == other.Decimals
}

// AtMost reports whether this amount does not exceed a ceiling.
//
// Two amounts in different assets, or in the same asset at different
// precisions, are not comparable at all. Returning false for them would read
// as "within the ceiling is false", which invites a caller to negate it;
// refusing outright is what keeps a USDT price from being checked against a
// TOS budget.
func (a Amount) AtMost(ceiling Amount) (bool, error) {
	if err := a.Validate(); err != nil {
		return false, err
	}
	if err := ceiling.Validate(); err != nil {
		return false, err
	}
	if !a.SameAsset(ceiling) {
		return false, errors.New("amounts in different assets cannot be compared")
	}
	return a.Units <= ceiling.Units, nil
}

// Add returns the sum, refusing an overflow rather than wrapping.
func (a Amount) Add(other Amount) (Amount, error) {
	if err := a.Validate(); err != nil {
		return Amount{}, err
	}
	if err := other.Validate(); err != nil {
		return Amount{}, err
	}
	if !a.SameAsset(other) {
		return Amount{}, errors.New("amounts in different assets cannot be added")
	}
	sum := a.Units + other.Units
	if sum < a.Units {
		return Amount{}, errors.New("amount overflows")
	}
	return Amount{Asset: a.Asset, Units: sum, Decimals: a.Decimals}, nil
}

// Equal reports exact equality, including asset and precision.
func (a Amount) Equal(other Amount) bool {
	return a.SameAsset(other) && a.Units == other.Units
}

// String renders an amount for a person. It is presentation: the number a
// caller acts on is Units, and nothing parses this back.
func (a Amount) String() string {
	if a.Decimals == 0 {
		return strconv.FormatUint(a.Units, 10) + " " + a.Asset
	}
	digits := strconv.FormatUint(a.Units, 10)
	for uint8(len(digits)) <= a.Decimals {
		digits = "0" + digits
	}
	split := len(digits) - int(a.Decimals)
	whole, fraction := digits[:split], strings.TrimRight(digits[split:], "0")
	if fraction == "" {
		return whole + " " + a.Asset
	}
	return whole + "." + fraction + " " + a.Asset
}
