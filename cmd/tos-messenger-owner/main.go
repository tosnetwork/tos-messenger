// Command tos-messenger-owner operates the owner-only approval boundary.
// It separates online challenge acquisition/submission from signing so the
// private key can remain on an isolated machine or be replaced by a hardware
// signer without changing the daemon protocol.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/tosnetwork/tos-messenger/internal/securefile"
	"github.com/tosnetwork/tos-messenger/pkg/localapi"
)

const decisionSchema = "tos.messaging.owner-decision.v1"

type decisionEnvelope struct {
	Schema          string           `json:"schema"`
	Request         localapi.Request `json:"request"`
	SigningBytesHex string           `json:"signing_bytes_hex"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "tos-messenger-owner:", err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	global := flag.NewFlagSet("tos-messenger-owner", flag.ContinueOnError)
	global.SetOutput(io.Discard)
	socket := global.String("socket", "", "clean absolute owner socket path")
	timeout := global.Duration("timeout", localapi.DefaultClientTimeout, "request timeout")
	if err := global.Parse(args); err != nil {
		return err
	}
	rest := global.Args()
	if len(rest) == 0 {
		return errors.New("usage: tos-messenger-owner [-socket PATH] <pending|prepare-grant|prepare-deny|sign|submit>")
	}
	if rest[0] == "sign" {
		return signCommand(rest[1:], output)
	}
	client, err := localapi.NewClient(*socket, *timeout)
	if err != nil {
		return err
	}
	switch rest[0] {
	case "pending":
		set := commandFlags("pending")
		limit := set.Int("limit", localapi.MaxEventsPerResponse, "maximum actions")
		if err := set.Parse(rest[1:]); err != nil || set.NArg() != 0 {
			return errors.New("usage: pending [-limit N]")
		}
		response, err := client.Call(context.Background(), localapi.Request{Op: localapi.OpPendingActions, Limit: *limit})
		if err != nil {
			return err
		}
		return writeJSON(output, response.Actions)
	case "prepare-grant":
		if len(rest) != 2 {
			return errors.New("usage: prepare-grant ACTION_ID")
		}
		return prepare(client, localapi.Request{Op: localapi.OpGrantAction, ActionID: rest[1]}, output)
	case "prepare-deny":
		set := commandFlags("prepare-deny")
		reason := set.String("reason", "", "owner-visible refusal reason")
		if err := set.Parse(rest[1:]); err != nil || set.NArg() != 1 || *reason == "" {
			return errors.New("usage: prepare-deny -reason TEXT ACTION_ID")
		}
		return prepare(client, localapi.Request{Op: localapi.OpDenyAction, ActionID: set.Arg(0), Reason: *reason}, output)
	case "submit":
		set := commandFlags("submit")
		path := set.String("decision", "", "signed decision JSON")
		if err := set.Parse(rest[1:]); err != nil || set.NArg() != 0 || *path == "" {
			return errors.New("usage: submit -decision FILE")
		}
		envelope, err := readDecision(*path)
		if err != nil {
			return err
		}
		if err := validateEnvelope(envelope, true); err != nil {
			return err
		}
		response, err := client.Call(context.Background(), envelope.Request)
		if err != nil {
			return err
		}
		return writeJSON(output, response)
	default:
		return errors.New("unknown owner command")
	}
}

func commandFlags(name string) *flag.FlagSet {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(io.Discard)
	return set
}

func prepare(client *localapi.Client, request localapi.Request, output io.Writer) error {
	issued, err := client.Call(context.Background(), localapi.Request{Op: localapi.OpChallenge})
	if err != nil {
		return err
	}
	request.Schema = localapi.RequestSchema
	request.Challenge = issued.Challenge
	preimage, err := localapi.DecisionBytes(request, issued.Challenge)
	if err != nil {
		return err
	}
	return writeJSON(output, decisionEnvelope{Schema: decisionSchema, Request: request, SigningBytesHex: hex.EncodeToString(preimage)})
}

func signCommand(args []string, output io.Writer) error {
	set := commandFlags("sign")
	keyPath := set.String("key", "", "0600 Ed25519 private key file containing 128 lowercase hex digits")
	decisionPath := set.String("decision", "", "prepared decision JSON")
	if err := set.Parse(args); err != nil || set.NArg() != 0 || *keyPath == "" || *decisionPath == "" {
		return errors.New("usage: sign -key FILE -decision FILE")
	}
	envelope, err := readDecision(*decisionPath)
	if err != nil {
		return err
	}
	if err := validateEnvelope(envelope, false); err != nil {
		return err
	}
	key, err := readPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	defer clear(key)
	signature, err := localapi.SignDecision(envelope.Request, envelope.Request.Challenge, key)
	if err != nil {
		return err
	}
	envelope.Request.OwnerSignature = signature
	return writeJSON(output, envelope)
}

func validateEnvelope(envelope decisionEnvelope, signed bool) error {
	if envelope.Schema != decisionSchema || !localapi.Deciding(envelope.Request.Op) {
		return errors.New("unsupported owner decision")
	}
	preimage, err := localapi.DecisionBytes(envelope.Request, envelope.Request.Challenge)
	if err != nil || envelope.SigningBytesHex != hex.EncodeToString(preimage) {
		return errors.New("owner decision signing bytes do not match its request")
	}
	if signed {
		raw, err := hex.DecodeString(envelope.Request.OwnerSignature)
		if err != nil || len(raw) != ed25519.SignatureSize || envelope.Request.OwnerSignature != strings.ToLower(envelope.Request.OwnerSignature) {
			return errors.New("owner decision has no canonical Ed25519 signature")
		}
	} else if envelope.Request.OwnerSignature != "" {
		return errors.New("prepared owner decision is already signed")
	}
	return nil
}

func readDecision(path string) (decisionEnvelope, error) {
	raw, err := readRegular(path, 64<<10, false)
	if err != nil {
		return decisionEnvelope{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var envelope decisionEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return decisionEnvelope{}, errors.New("decode owner decision")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return decisionEnvelope{}, errors.New("owner decision has trailing JSON")
	}
	return envelope, nil
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := readRegular(path, 130, true)
	if err != nil {
		return nil, err
	}
	text := strings.TrimSuffix(string(raw), "\n")
	if len(text) != ed25519.PrivateKeySize*2 || text != strings.ToLower(text) {
		return nil, errors.New("owner key must be 128 lowercase hex digits")
	}
	decoded, err := hex.DecodeString(text)
	if err != nil {
		return nil, errors.New("decode owner key")
	}
	key := ed25519.PrivateKey(decoded)
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	if !bytes.Equal(derived, key) {
		clear(key)
		return nil, errors.New("owner private key has an inconsistent public half")
	}
	return key, nil
}

func readRegular(path string, maximum int64, secret bool) ([]byte, error) {
	raw, err := securefile.ReadBoundedRegular(path, maximum)
	if err != nil {
		return nil, err
	}
	if secret {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("owner key must remain a regular file")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != 0o600 {
			return nil, errors.New("owner key must be owned by this user with mode 0600")
		}
	}
	return raw, nil
}

func writeJSON(output io.Writer, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
