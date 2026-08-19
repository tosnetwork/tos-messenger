package payload

import (
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
)

var (
	// mediaTypes is the closed set a text body may declare. An open media type
	// field is a rendering instruction from a stranger.
	mediaTypes = map[string]struct{}{
		"text/plain; charset=utf-8": {},
		"text/markdown":             {},
	}
	// protocolPattern matches the name of a protocol this one carries but does
	// not define.
	protocolPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z0-9]+)*$`)
	// tokenPattern matches a short machine-readable label.
	tokenPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)
)

// requireText enforces a non-empty, bounded, single-purpose string.
func requireText(name, value string, maximum int) error {
	if value == "" {
		return errors.New(name + " is required")
	}
	if len(value) > maximum {
		return errors.New(name + " exceeds its bound")
	}
	if !utf8.ValidString(value) {
		return errors.New(name + " is not valid UTF-8")
	}
	// A control character in a field a human or a log will render is a
	// formatting instruction the sender should not get to give.
	if strings.ContainsAny(value, "\x00\r") {
		return errors.New(name + " contains control characters")
	}
	return nil
}

// optionalText allows an empty value and otherwise applies requireText.
func optionalText(name, value string, maximum int) error {
	if value == "" {
		return nil
	}
	return requireText(name, value, maximum)
}

func requireMatch(name, value string, pattern *regexp.Regexp) error {
	if !pattern.MatchString(value) {
		return errors.New(name + " is not a valid identifier")
	}
	return nil
}

func optionalMatch(name, value string, pattern *regexp.Regexp) error {
	if value == "" {
		return nil
	}
	return requireMatch(name, value, pattern)
}

func requireDigest(name, value string) error {
	if !canon.ValidDigest(value) {
		return errors.New(name + " is not a usable digest")
	}
	return nil
}

func optionalDigest(name, value string) error {
	if value == "" {
		return nil
	}
	return requireDigest(name, value)
}

func requireTime(name string, value uint64) error {
	if value == 0 {
		return errors.New(name + " is required")
	}
	return nil
}

func requireMember(name, value string, members map[string]struct{}) error {
	if _, known := members[value]; !known {
		return errors.New(name + " is not a recognised value")
	}
	return nil
}

// eventReference is the shape shared by every payload that points at another
// event in the same conversation.
func requireEvent(name, value string) error {
	return requireMatch(name, value, ids.Event)
}
