package payload

import (
	"bytes"
	"errors"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

const MaxIntentApplicationBytes = 64 << 10

// IntentApplication transports a canonical, explicitly non-authorizing first
// contact. Messenger authenticates the sender and preserves the exact bytes;
// only a later Agreement proposal can create commercial authority.
type IntentApplication struct{ CanonicalApplication []byte }

func (IntentApplication) Schema() string { return "tos.messaging.payload.intent-application.v1" }

func (application IntentApplication) Validate() error {
	if len(application.CanonicalApplication) == 0 || len(application.CanonicalApplication) > MaxIntentApplicationBytes {
		return errors.New("Intent application is absent or oversized")
	}
	_, err := commerce.DecodeIntentApplication(application.CanonicalApplication)
	return err
}

func (application IntentApplication) encode(buffer *bytes.Buffer) {
	canon.Bytes(buffer, application.CanonicalApplication)
}

func decodeIntentApplication(reader *canon.Reader) Payload {
	return IntentApplication{CanonicalApplication: reader.Bytes(MaxIntentApplicationBytes)}
}
