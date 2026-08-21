package publicchannel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tosutils-go/adnl"
)

func TestNativeOverlayADNLRLDPHistoryRoundTrip(t *testing.T) {
	if publicChannelRaceEnabled {
		t.Skip("tosutils-go's TL serializer is incompatible with race/checkptr; make test-adnl runs this test without race")
	}
	profile, authority, authorityKey, publisher, publisherKey, delegations := storeFixture(t)
	digest, _ := profile.Digest()
	first := signedPost(t, profile, digest, publisher, publisherKey, 1, "", nil, channelNow, "native root")
	firstID, _ := first.ID()
	hide, err := SignEvent(Event{ChannelID: profile.ChannelID, ProfileDigest: digest,
		PublisherAgentID: authority.AgentID, PublisherEndpointID: authority.EndpointID,
		Sequence: 1, Parents: []string{firstID}, PublishedAtUnix: channelNow + 1,
		Kind: KindHide, TargetEventID: firstID}, authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	hideID, _ := hide.ID()
	now := time.Unix(int64(channelNow+2), 0)
	want, err := VerifyHistory(profile, []Event{hide, first}, authority, delegations, now)
	if err != nil {
		t.Fatal(err)
	}
	available := map[string]Event{firstID: first, hideID: hide}
	serverKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	clientKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x32}, ed25519.SeedSize))

	for attempt := 0; attempt < 2; attempt++ {
		got := runNativeCarrierPair(t, profile, authority, delegations, now, serverKey, clientKey, want, available, first)
		if got.Digest() != want.Digest() {
			t.Fatalf("attempt %d history digest = %q, want %q", attempt, got.Digest(), want.Digest())
		}
	}
}

func runNativeCarrierPair(t *testing.T, profile Profile, authority identity.Delegation,
	delegations map[string]identity.Delegation, now time.Time, serverKey, clientKey ed25519.PrivateKey,
	want History, available map[string]Event, announced Event) History {
	t.Helper()
	listen := reserveNativeUDPAddress(t)
	serverGateway := adnl.NewGateway(serverKey)
	clientGateway := adnl.NewGateway(clientKey)
	serverCarriers := make(chan *NativeCarrier, 1)
	serverErrors := make(chan error, 1)
	serverGateway.SetConnectionHandler(func(peer adnl.Peer) error {
		guard, err := NewSyncGuard(profile.ChannelID, want.ProfileDigest(), DefaultSyncLimits())
		if err != nil {
			return err
		}
		carrier, err := NewNativeCarrier(peer, serverKey, NativeCarrierConfig{Profile: profile,
			Authority: authority, Delegations: delegations, Now: func() time.Time { return now }, Guard: guard,
			Provider: func(FetchRequest) (map[string]Event, error) { return available, nil },
			OnEvent: func(_ string, event Event) error {
				id, _ := event.ID()
				wantID, _ := announced.ID()
				if id != wantID {
					return errors.New("native Overlay announced another Event")
				}
				select {
				case serverErrors <- nil:
				default:
				}
				return nil
			},
		})
		if err != nil {
			return err
		}
		select {
		case serverCarriers <- carrier:
		default:
			carrier.Close()
		}
		return nil
	})
	if err := serverGateway.StartServer(listen); err != nil {
		t.Fatal(err)
	}
	defer serverGateway.Close()
	if err := clientGateway.StartClient(); err != nil {
		t.Fatal(err)
	}
	defer clientGateway.Close()
	peer, err := clientGateway.RegisterClient(listen, serverKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	clientGuard, err := NewSyncGuard(profile.ChannelID, want.ProfileDigest(), DefaultSyncLimits())
	if err != nil {
		t.Fatal(err)
	}
	heads := make(chan Head, 1)
	clientCarrier, err := NewNativeCarrier(peer, clientKey, NativeCarrierConfig{Profile: profile,
		Authority: authority, Delegations: delegations, Now: func() time.Time { return now }, Guard: clientGuard,
		OnHead: func(_ string, head Head) error {
			select {
			case heads <- head:
			default:
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientCarrier.Close()
	pingCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	_, err = peer.Ping(pingCtx)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	var serverCarrier *NativeCarrier
	select {
	case serverCarrier = <-serverCarriers:
	case <-time.After(3 * time.Second):
		t.Fatal("native Overlay server carrier was not assembled")
	}
	defer serverCarrier.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := serverCarrier.PublishHead(ctx, want.Head()); err != nil {
		t.Fatal(err)
	}
	var head Head
	select {
	case head = <-heads:
	case <-ctx.Done():
		t.Fatal("native Overlay head announcement was not delivered")
	}
	if err := clientCarrier.PublishEvent(ctx, announced); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serverErrors:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("native Overlay Event announcement was not delivered")
	}

	var known []Event
	for {
		request, needed, err := NextFetch(head, known)
		if err != nil {
			t.Fatal(err)
		}
		if !needed {
			break
		}
		fetched, unavailable, err := clientCarrier.Fetch(ctx, request)
		if err != nil || len(unavailable) != 0 {
			t.Fatalf("native RLDP fetch: unavailable=%v err=%v", unavailable, err)
		}
		known, err = MergeFetchedEvents(known, fetched)
		if err != nil {
			t.Fatal(err)
		}
	}
	got, err := VerifySyncedHistory(head, profile, known, authority, delegations, now)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func reserveNativeUDPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.LocalAddr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}
