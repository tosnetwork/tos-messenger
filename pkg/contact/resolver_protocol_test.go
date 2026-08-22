package contact

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1/tosservicev1connect"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativeclient"
	"google.golang.org/protobuf/proto"
)

type protocolDNSService struct {
	t        *testing.T
	response *nativev1.ResolveDNSAliasResponse
}

func (s protocolDNSService) ResolveDNSAlias(_ context.Context,
	request *connect.Request[nativev1.ResolveDNSAliasRequest],
) (*connect.Response[nativev1.ResolveDNSAliasResponse], error) {
	s.t.Helper()
	if request.Header().Get("Authorization") != "Bearer dns-test-token" {
		s.t.Error("native client omitted the DNS bearer token")
	}
	if request.Msg.Name != "alice.tos" || request.Msg.Kind != nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_MESSENGER {
		s.t.Errorf("unexpected wire request: %+v", request.Msg)
	}
	return connect.NewResponse(proto.Clone(s.response).(*nativev1.ResolveDNSAliasResponse)), nil
}

func TestResolveDNSContactAcrossServiceProtocolConnectBoundary(t *testing.T) {
	now := testNow()
	agentID := testAgent("9")
	response, account := testDNSResponse(agentID, now)
	path, handler := tosservicev1connect.NewDNSAliasServiceHandler(protocolDNSService{t: t, response: response})
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := nativeclient.New(nativeclient.Config{
		BaseURL: server.URL, BearerToken: "dns-test-token", Insecure: true,
	})
	if err != nil {
		t.Fatalf("construct service-protocol client: %v", err)
	}
	defer client.Close()
	directory := &contactDirectory{}
	resolver := testResolver(client, directory, map[string]string{agentID: account}, now)
	result, err := resolver.Resolve(context.Background(), "alice.tos")
	if err != nil {
		t.Fatalf("cross-protocol contact resolution: %v", err)
	}
	if result.AgentID != agentID || len(directory.calls) != 1 || directory.calls[0] != agentID {
		t.Fatalf("wire result did not enter the ID-bound directory chain: result=%+v calls=%v", result, directory.calls)
	}
}
