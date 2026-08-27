package localapi

import "testing"

func TestMessengerSendAuthorizesCommerceProfileEvent(t *testing.T) {
	if !economicKindMatchesEffect("messenger.send", "commerce.profile-event") {
		t.Fatal("generic commerce profile event is not carried by the released Messenger action")
	}
	if economicKindMatchesEffect("messenger.contact", "commerce.profile-event") {
		t.Fatal("first-contact authority unexpectedly authorizes an economic object")
	}
}
