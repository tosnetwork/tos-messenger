// Command tos-device-fork-evidence assembles or verifies portable proof that
// one finalized Messaging Endpoint published two non-orderable device sets at
// the same freshness watermark.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/securefile"
	"github.com/tosnetwork/tos-messenger/pkg/daemon"
	"github.com/tosnetwork/tos-messenger/pkg/directory"
	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
)

const verificationSchema = "tos.messaging.device-fork-verification.v1"

type options struct {
	mode, config, policy, evidence                         string
	firstDescriptor, firstSet, secondDescriptor, secondSet string
}

func main() {
	var value options
	flag.StringVar(&value.mode, "mode", "", "assemble or verify")
	flag.StringVar(&value.config, "config", "", "daemon configuration used for live finalized authority")
	flag.StringVar(&value.policy, "policy", "", "committed Descriptor policy JSON")
	flag.StringVar(&value.evidence, "evidence", "", "fork evidence JSON (verify mode)")
	flag.StringVar(&value.firstDescriptor, "first-descriptor", "", "first signed Descriptor JSON")
	flag.StringVar(&value.firstSet, "first-set", "", "first complete bundle-set JSON")
	flag.StringVar(&value.secondDescriptor, "second-descriptor", "", "second signed Descriptor JSON")
	flag.StringVar(&value.secondSet, "second-set", "", "second complete bundle-set JSON")
	flag.Parse()
	if err := run(value, os.Stdout, time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, "tos-device-fork-evidence:", err)
		os.Exit(1)
	}
}

func (o options) validate() error {
	if o.mode != "assemble" && o.mode != "verify" {
		return errors.New("mode must be assemble or verify")
	}
	if o.config == "" || o.policy == "" {
		return errors.New("daemon config and Descriptor policy are required")
	}
	if o.mode == "verify" {
		if o.evidence == "" || o.firstDescriptor != "" || o.firstSet != "" || o.secondDescriptor != "" || o.secondSet != "" {
			return errors.New("verify mode accepts exactly one evidence file")
		}
		return nil
	}
	if o.evidence != "" || o.firstDescriptor == "" || o.firstSet == "" || o.secondDescriptor == "" || o.secondSet == "" {
		return errors.New("assemble mode requires exactly two Descriptor and bundle-set pairs")
	}
	return nil
}

func run(value options, output io.Writer, now time.Time) error {
	if err := value.validate(); err != nil {
		return err
	}
	if output == nil || now.IsZero() {
		return errors.New("invalid verification runtime")
	}
	config, err := daemon.LoadConfig(value.config)
	if err != nil {
		return err
	}
	delegation, err := daemon.VerifyFinalizedDelegation(config, now)
	if err != nil {
		return errors.New("verify finalized Endpoint delegation: " + err.Error())
	}
	policyRaw, err := securefile.ReadBoundedRegular(value.policy, directory.MaxDescriptorPolicyWireBytes)
	if err != nil {
		return errors.New("read Descriptor policy: " + err.Error())
	}
	policy, err := directory.DecodeDescriptorPolicyJSON(policyRaw)
	if err != nil {
		return errors.New("decode Descriptor policy: " + err.Error())
	}
	policyDigest, err := policy.Digest()
	if err != nil || policyDigest != delegation.ContactDescriptorPolicyDigest {
		return errors.New("Descriptor policy does not match finalized delegation")
	}

	if value.mode == "assemble" {
		raw, err := assemble(value, delegation, policy, now)
		if err != nil {
			return err
		}
		_, err = output.Write(append(raw, '\n'))
		return err
	}
	raw, err := securefile.ReadBoundedRegular(value.evidence, directory.MaxDeviceForkEvidenceWireBytes)
	if err != nil {
		return errors.New("read device fork evidence: " + err.Error())
	}
	proof, err := directory.VerifyDeviceForkEvidence(raw, delegation, policy, now)
	if err != nil {
		return errors.New("verify device fork evidence: " + err.Error())
	}
	return json.NewEncoder(output).Encode(struct {
		Schema       string `json:"schema"`
		EndpointID   string `json:"messaging_endpoint_id"`
		FirstDigest  string `json:"first_set_digest"`
		SecondDigest string `json:"second_set_digest"`
		IssuedAtUnix uint64 `json:"issued_at_unix"`
	}{verificationSchema, delegation.EndpointID, proof.CurrentDigest, proof.CandidateDigest, proof.IssuedAtUnix})
}

func assemble(value options, delegation identity.Delegation, policy directory.DescriptorPolicy, now time.Time) ([]byte, error) {
	firstDescriptor, firstSet, err := readPublication(value.firstDescriptor, value.firstSet)
	if err != nil {
		return nil, errors.New("read first publication: " + err.Error())
	}
	secondDescriptor, secondSet, err := readPublication(value.secondDescriptor, value.secondSet)
	if err != nil {
		return nil, errors.New("read second publication: " + err.Error())
	}
	return directory.NewDeviceForkEvidence(delegation, policy, firstDescriptor, firstSet,
		secondDescriptor, secondSet, now)
}

func readPublication(descriptorPath, setPath string) (directory.Descriptor, []e2ee.Bundle, error) {
	descriptorRaw, err := securefile.ReadBoundedRegular(descriptorPath, directory.MaxDescriptorWireBytes)
	if err != nil {
		return directory.Descriptor{}, nil, err
	}
	descriptor, err := directory.DecodeDescriptorJSON(descriptorRaw)
	if err != nil {
		return directory.Descriptor{}, nil, err
	}
	setRaw, err := securefile.ReadBoundedRegular(setPath, e2ee.MaxBundleSetWireBytes)
	if err != nil {
		return directory.Descriptor{}, nil, err
	}
	bundles, err := e2ee.DecodeBundleSetJSON(setRaw)
	if err != nil {
		return directory.Descriptor{}, nil, err
	}
	return descriptor, bundles, nil
}
