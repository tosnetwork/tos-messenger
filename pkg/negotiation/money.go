package negotiation

import (
	"bytes"
	"errors"
	"math/big"
	"regexp"
	"strings"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

const (
	// MaxDecimals bounds an asset's precision.
	MaxDecimals = 36
	// MaxAtomicDigits bounds an atomic amount. It is above what 256 bits can
	// express, and it exists so a peer's number cannot become this process's
	// allocation.
	MaxAtomicDigits = 78
)

var (
	atomicPattern  = regexp.MustCompile(`^(0|[1-9][0-9]{0,77})$`)
	accountPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	codeHashRegexp = regexp.MustCompile(`^tvm-cell-sha256:[0-9a-f]{64}$`)
)

// Asset is the identity of one asset.
//
// A ticker is not an identity. Two contracts may both call themselves USDT,
// and on two networks that is the normal case rather than an attack; an
// agreement that named its asset by ticker would let a counterparty deliver a
// different token that renders the same way. What identifies an asset is the
// network it lives on, the master contract it lives under, the wallet code
// that moves it, and its precision. The network is part of the identity for
// the same reason the code hashes are: the same workchain, account and code
// hashes can exist on another TOS network, and an asset identity that omitted
// it would give two different assets one digest -- and, through the price,
// give identical terms on two networks one digest, so a cross-network replay
// would hash to the commitment it replays.
type Asset struct {
	// Network is the TOS network the asset lives on, committed into every
	// digest the asset is folded into.
	Network   Network
	Workchain int32
	// AccountID is the master contract account, in lowercase hex.
	AccountID string
	// MasterCodeHash prevents a different implementation being treated as the
	// same protocol asset.
	MasterCodeHash string
	WalletCodeHash string
	Decimals       uint32
}

// Validate enforces a usable asset identity.
func (a Asset) Validate() error {
	if err := a.Network.Validate(); err != nil {
		return errors.New("asset names no network")
	}
	if a.Workchain < -128 || a.Workchain > 127 {
		return errors.New("asset workchain is outside the addressable range")
	}
	if !accountPattern.MatchString(a.AccountID) {
		return errors.New("asset names no master contract account")
	}
	if !codeHashRegexp.MatchString(a.MasterCodeHash) {
		return errors.New("asset names no master code hash")
	}
	if !codeHashRegexp.MatchString(a.WalletCodeHash) {
		return errors.New("asset names no wallet code hash")
	}
	if a.Decimals > MaxDecimals {
		return errors.New("asset precision exceeds its bound")
	}
	return nil
}

// Same reports whether two identities are the same asset. The network is part
// of the comparison: the same contract tuple on another network is a different
// asset.
func (a Asset) Same(other Asset) bool {
	return a.Network.Same(other.Network) &&
		a.Workchain == other.Workchain && a.AccountID == other.AccountID &&
		a.MasterCodeHash == other.MasterCodeHash && a.WalletCodeHash == other.WalletCodeHash &&
		a.Decimals == other.Decimals
}

func (a Asset) canonical(buffer *bytes.Buffer) {
	a.Network.canonical(buffer)
	canon.Uint32(buffer, uint32(a.Workchain))
	canon.Text(buffer, a.AccountID)
	canon.Text(buffer, a.MasterCodeHash)
	canon.Text(buffer, a.WalletCodeHash)
	canon.Uint32(buffer, a.Decimals)
}

// Proto returns the protocol form of an asset identity, so the same identity
// travels to the chain side without being re-expressed. The protocol form
// carries no network field: on the chain side the network is established by
// which network the state was resolved from, and it is compared there against
// the negotiation's binding rather than restated inside the asset.
func (a Asset) Proto() (*nativev1.TOSAssetIdentityV1, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	account, err := decodeHex(a.AccountID)
	if err != nil {
		return nil, err
	}
	return &nativev1.TOSAssetIdentityV1{
		Master: &nativev1.TOSContractIdentityV1{
			Workchain: a.Workchain, AccountId: account, CodeHash: a.MasterCodeHash,
		},
		WalletCodeHash: a.WalletCodeHash,
		Decimals:       a.Decimals,
	}, nil
}

// Money is an exact quantity of one asset.
//
// The quantity is an integer count of atomic units carried as a canonical
// decimal string, which is what the chain carries. It is never a float and
// never a fixed-width integer: a price compared, summed, or rounded in
// floating point can differ between two implementations that both believe they
// agreed, and a 64-bit count cannot express eighteen decimal places of any
// ordinary token.
type Money struct {
	Asset Asset
	// Atomic is the count of atomic units: no sign, no leading zeros, no
	// separators. One value has one encoding, because two encodings of one
	// price is two digests of one agreement.
	Atomic string
}

// NewMoney builds an amount from an integer count of atomic units.
func NewMoney(asset Asset, atomic *big.Int) (Money, error) {
	if atomic == nil || atomic.Sign() < 0 {
		return Money{}, errors.New("an amount cannot be negative or absent")
	}
	value := Money{Asset: asset, Atomic: atomic.String()}
	if err := value.Validate(); err != nil {
		return Money{}, err
	}
	return value, nil
}

// Validate enforces a usable amount.
func (m Money) Validate() error {
	if err := m.Asset.Validate(); err != nil {
		return err
	}
	if !atomicPattern.MatchString(m.Atomic) {
		return errors.New("an amount must be a canonical decimal count of atomic units")
	}
	return nil
}

// Int returns the atomic count.
func (m Money) Int() (*big.Int, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	value, ok := new(big.Int).SetString(m.Atomic, 10)
	if !ok {
		return nil, errors.New("invalid atomic amount")
	}
	return value, nil
}

// SameAsset reports whether two amounts are even comparable.
func (m Money) SameAsset(other Money) bool { return m.Asset.Same(other.Asset) }

// AtMost reports whether this amount is within a ceiling.
//
// Two amounts of different assets are not comparable, and answering anyway
// would be inventing an exchange rate.
func (m Money) AtMost(ceiling Money) (bool, error) {
	if !m.SameAsset(ceiling) {
		return false, errors.New("amounts of different assets are not comparable")
	}
	left, err := m.Int()
	if err != nil {
		return false, err
	}
	right, err := ceiling.Int()
	if err != nil {
		return false, err
	}
	return left.Cmp(right) <= 0, nil
}

// Add sums two amounts of one asset. There is no overflow: the count is
// arbitrary precision, which is why it is carried as one.
func (m Money) Add(other Money) (Money, error) {
	if !m.SameAsset(other) {
		return Money{}, errors.New("amounts of different assets cannot be added")
	}
	left, err := m.Int()
	if err != nil {
		return Money{}, err
	}
	right, err := other.Int()
	if err != nil {
		return Money{}, err
	}
	return NewMoney(m.Asset, new(big.Int).Add(left, right))
}

// Equal reports whether two amounts are the same amount of the same asset.
func (m Money) Equal(other Money) bool {
	return m.SameAsset(other) && m.Atomic == other.Atomic
}

// Zero returns nothing, of this asset.
func (m Money) Zero() Money { return Money{Asset: m.Asset, Atomic: "0"} }

// String renders an amount for a person.
//
// It is presentation. The value acted on is the atomic count, and nothing
// parses this back: a renderer that could be parsed would eventually be
// treated as the authority, which is the confusion the structured form exists
// to prevent.
func (m Money) String() string {
	if m.Asset.Decimals == 0 {
		return m.Atomic + " (" + m.Asset.AccountID[:8] + ")"
	}
	digits := m.Atomic
	for uint32(len(digits)) <= m.Asset.Decimals {
		digits = "0" + digits
	}
	split := uint32(len(digits)) - m.Asset.Decimals
	whole, fraction := digits[:split], digits[split:]
	fraction = strings.TrimRight(fraction, "0")
	if fraction == "" {
		return whole + " (" + m.Asset.AccountID[:8] + ")"
	}
	return whole + "." + fraction + " (" + m.Asset.AccountID[:8] + ")"
}

func (m Money) canonical(buffer *bytes.Buffer) {
	m.Asset.canonical(buffer)
	canon.Text(buffer, m.Atomic)
}

func decodeHex(value string) ([]byte, error) {
	raw := make([]byte, len(value)/2)
	for index := 0; index < len(raw); index++ {
		high, lowErr := hexDigit(value[index*2]), hexDigit(value[index*2+1])
		if high < 0 || lowErr < 0 {
			return nil, errors.New("invalid hex value")
		}
		raw[index] = byte(high<<4 | lowErr)
	}
	return raw, nil
}

func hexDigit(character byte) int {
	switch {
	case character >= '0' && character <= '9':
		return int(character - '0')
	case character >= 'a' && character <= 'f':
		return int(character-'a') + 10
	default:
		return -1
	}
}
