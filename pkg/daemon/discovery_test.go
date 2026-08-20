package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
)

const validDHTGlobalConfig = `{
  "@type":"config.global",
  "dht":{"@type":"dht.config.global","k":6,"a":3,"static_nodes":{"@type":"dht.nodes","nodes":[{
    "@type":"dht.node",
    "id":{"@type":"pub.ed25519","key":"6PGkPQSbyFp12esf1NqmDOaLoFA8i9+Mp5+cAx5wtTU="},
    "addr_list":{"@type":"adnl.addressList","addrs":[{"@type":"adnl.address.udp","ip":-1185526007,"port":22096}],"version":0,"reinit_date":0,"priority":0,"expire_at":0},
    "version":-1,
    "signature":"L4N1+dzXLlkmT5iPnvsmsixzXU0L6kPKApqMdcrGP5d9ssMhn69SzHFK+yIzvG6zQ9oRb4TnqPBaKShjjj2OBg=="
  }]}},
  "liteservers":[],"validator":{}
}`

func TestProductionDiscoveryBuildsTheRouteNeutralChain(t *testing.T) {
	config := testConfig(t)
	globalPath := filepath.Join(filepath.Dir(config.StateDir), "global.json")
	if err := os.WriteFile(globalPath, []byte(validDHTGlobalConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	config.Discovery = DiscoveryConfig{
		Mode: DiscoveryTOSDHTHTTPS, DHTGlobalConfigPath: globalPath,
		Peers: []PeerDelegationConfig{{AgentID: "agent_" + strings.Repeat("5", 64),
			DelegationPath:       filepath.Join(filepath.Dir(config.StateDir), "peer.json"),
			DescriptorPolicyPath: filepath.Join(filepath.Dir(config.StateDir), "peer-policy.json")}},
	}
	journal, err := openJournalForDiscoveryTest(config)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	runtime, err := (productionDiscoveryBuilder{}).Build(config, journal, nil)
	if err != nil {
		t.Fatal(err)
	}
	if runtime == nil || runtime.runner == nil || len(runtime.peers) != 1 {
		t.Fatalf("runtime=%+v", runtime)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProductionDiscoveryRefusesUnverifiedBootstrap(t *testing.T) {
	config := testConfig(t)
	globalPath := filepath.Join(filepath.Dir(config.StateDir), "global.json")
	if err := os.WriteFile(globalPath, []byte(`{"dht":{"static_nodes":{"nodes":[]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	config.Discovery = DiscoveryConfig{
		Mode: DiscoveryTOSDHTHTTPS, DHTGlobalConfigPath: globalPath,
		Peers: []PeerDelegationConfig{{AgentID: "agent_" + strings.Repeat("5", 64),
			DelegationPath:       filepath.Join(filepath.Dir(config.StateDir), "peer.json"),
			DescriptorPolicyPath: filepath.Join(filepath.Dir(config.StateDir), "peer-policy.json")}},
	}
	journal, err := openJournalForDiscoveryTest(config)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	if _, err := (productionDiscoveryBuilder{}).Build(config, journal, nil); err == nil {
		t.Fatal("accepted an empty DHT bootstrap set")
	}
}

func openJournalForDiscoveryTest(config Config) (*eventlog.Journal, error) {
	return eventlog.Open(config.StateDir)
}
