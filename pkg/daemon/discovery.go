package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/securefile"
	"github.com/tosnetwork/tos-messenger/pkg/directory"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tosutils-go/adnl"
	"github.com/tosnetwork/tosutils-go/adnl/dht"
	"github.com/tosnetwork/tosutils-go/liteclient"
)

const (
	maxDHTGlobalConfigBytes = 1 << 20
	maxDHTBootstrapNodes    = 256
)

type directoryRunner interface {
	Run(context.Context, []string, time.Duration) error
}

type discoveryRuntime struct {
	runner directoryRunner
	peers  []string
	close  func()
}

func (r *discoveryRuntime) Close() error {
	if r != nil && r.close != nil {
		r.close()
	}
	return nil
}

type discoveryBuilder interface {
	Build(Config, *eventlog.Journal, Observer) (*discoveryRuntime, error)
}

type productionDiscoveryBuilder struct{}

func (productionDiscoveryBuilder) Build(config Config, journal *eventlog.Journal, observer Observer) (*discoveryRuntime, error) {
	if config.Discovery.Mode == DiscoveryNone {
		return nil, nil
	}
	files := make([]directory.DelegationFile, 0, len(config.Discovery.Peers))
	peers := make([]string, 0, len(config.Discovery.Peers))
	for _, peer := range config.Discovery.Peers {
		files = append(files, directory.DelegationFile{AgentID: peer.AgentID, Path: peer.DelegationPath,
			DescriptorPolicyPath: peer.DescriptorPolicyPath})
		peers = append(peers, peer.AgentID)
	}
	delegations, err := directory.NewFileDelegations(files)
	if err != nil {
		return nil, errors.New("configure peer delegation bootstrap: " + err.Error())
	}

	rawConfig, err := securefile.ReadBoundedRegular(config.Discovery.DHTGlobalConfigPath, maxDHTGlobalConfigBytes)
	if err != nil {
		return nil, errors.New("read DHT global configuration: " + err.Error())
	}
	var global liteclient.GlobalConfig
	if err := json.Unmarshal(rawConfig, &global); err != nil {
		return nil, errors.New("decode DHT global configuration")
	}
	nodes, err := dht.BootstrapNodesFromConfig(&global)
	if err != nil || len(nodes) == 0 || len(nodes) > maxDHTBootstrapNodes {
		return nil, errors.New("DHT global configuration has an invalid bootstrap set")
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.New("generate ephemeral DHT client identity")
	}
	gateway := adnl.NewGateway(private)
	if err := gateway.StartClient(); err != nil {
		return nil, errors.New("start ephemeral ADNL DHT client: " + err.Error())
	}
	client, err := dht.NewClientFromConfig(gateway, &global)
	if err != nil {
		_ = gateway.Close()
		return nil, errors.New("construct DHT client: " + err.Error())
	}
	if client.RoutingTableStats().ActiveNodes == 0 {
		client.Close()
		return nil, errors.New("DHT global configuration has no verified bootstrap node")
	}
	objects, err := directory.NewHTTPSObjects(directory.HTTPSObjectConfig{
		RequestTimeout: time.Duration(config.Discovery.HTTPSRequestTimeoutSeconds) * time.Second,
		ConnectTimeout: time.Duration(config.Discovery.HTTPSConnectTimeoutSeconds) * time.Second,
	})
	if err != nil {
		client.Close()
		return nil, errors.New("construct HTTPS object client: " + err.Error())
	}
	resolver, chain, err := finalizedResolver(config)
	if err != nil {
		objects.CloseIdleConnections()
		client.Close()
		return nil, errors.New("construct finalized peer resolver: " + err.Error())
	}
	devices, err := journal.OpenDevices()
	if err != nil {
		objects.CloseIdleConnections()
		client.Close()
		return nil, errors.New("open peer device ledger: " + err.Error())
	}
	source := directory.NetworkRefreshSource{
		Delegations: delegations,
		Policies:    delegations,
		Locators:    directory.TOSDHT{Client: client},
		Objects:     objects,
	}
	manager := &directory.Manager{
		Refresher: directory.Refresher{
			Source: source, Resolver: resolver, Network: config.Network(), Chain: chain,
			Admitter: devices,
		},
		Lead:     config.Discovery.RefreshLead(),
		Observer: daemonRefreshObserver{observer: observer},
	}
	return &discoveryRuntime{runner: manager, peers: peers, close: func() {
		objects.CloseIdleConnections()
		client.Close()
	}}, nil
}

type daemonRefreshObserver struct{ observer Observer }

func (o daemonRefreshObserver) RefreshCompleted(agentID string, _ directory.RefreshResult, err error) {
	if err != nil && o.observer != nil {
		o.observer.Failed("directory refresh "+agentID, err)
	}
}
