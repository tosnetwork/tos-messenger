package e2ee_test

import (
	"strings"
	"testing"

	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/e2ee/conformance"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

func candidateBinding() e2ee.Binding {
	return e2ee.Binding{
		Network: &nativev1.NetworkDomain{
			NetworkId:       "tos-local",
			GenesisRootHash: strings.Repeat("a", 64),
			GenesisFileHash: strings.Repeat("b", 64),
		},
		AlgorithmID:         e2ee.DefaultCandidateAlgorithmID,
		ConversationID:      "conv_" + strings.Repeat("1", 64),
		SenderAgentID:       "agent_" + strings.Repeat("2", 64),
		SenderEndpointID:    "mep_" + strings.Repeat("3", 64),
		SenderDeviceID:      "dev_" + strings.Repeat("4", 64),
		RecipientAgentID:    "agent_" + strings.Repeat("5", 64),
		RecipientEndpointID: "mep_" + strings.Repeat("6", 64),
		RecipientDeviceID:   "dev_" + strings.Repeat("7", 64),
	}
}

func TestDefaultCandidateClearsConformanceFloor(t *testing.T) {
	result := conformance.Verify(e2ee.NewDefaultSuite(), candidateBinding())
	if failed := result.Failed(); len(failed) != 0 {
		t.Fatalf("default candidate failed conformance: %+v", failed)
	}
}

func TestDefaultCandidateIdentifierMatchesBinding(t *testing.T) {
	suite := e2ee.NewDefaultSuite()
	if suite.AlgorithmID() != candidateBinding().AlgorithmID {
		t.Fatalf("suite identifier %q does not match default binding", suite.AlgorithmID())
	}
}
