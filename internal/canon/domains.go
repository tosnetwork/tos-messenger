package canon

// Domain separators for every signed or digest-committed object.
//
// They live in one list because a reused separator is not a merge conflict, it
// is a signature-confusion defect: two object kinds that share a namespace can
// produce the same preimage, and a signature over one becomes a valid
// signature over the other. Each package is internally consistent when that
// happens, so nothing else catches it. The uniqueness test beside this file
// does.
//
// Adding an object means adding a separator here first.
const (
	// DomainEndpointDelegation namespaces a Messaging Endpoint delegation.
	DomainEndpointDelegation = "tos.messaging.endpoint-delegation.v1\x00"
	// DomainEndpointID namespaces the endpoint identifier derivation.
	DomainEndpointID = "tos.messaging.endpoint-id.v1\x00"
	// DomainNegotiationRecord namespaces the on-disk name of one negotiation,
	// so an identifier a caller chose cannot name a path.
	DomainNegotiationRecord = "tos.messaging.negotiation-record.v1\x00"
	// DomainBudget namespaces the identifier of one asset's budget.
	DomainBudget = "tos.messaging.budget.v1\x00"
	// DomainNegotiationTerms namespaces one set of agreed terms.
	DomainNegotiationTerms = "tos.messaging.negotiation-terms.v1\x00"
	// DomainOwnerDecision namespaces what an owner signs to authorise one
	// decision on their own interface.
	DomainOwnerDecision = "tos.messaging.owner-decision.v1\x00"
	// DomainMandate namespaces a standing authorisation the owner placed.
	DomainMandate = "tos.messaging.mandate.v1\x00"
	// DomainAgentAction namespaces the content-addressed identifier of an
	// action an Agent proposes to take.
	DomainAgentAction = "tos.messaging.agent-action.v1\x00"
	// DomainPayload prefixes every typed event body. The body's own schema
	// follows it, so bytes that parse under one schema cannot be replayed as
	// another.
	DomainPayload = "tos.messaging.payload.v1\x00"
	// DomainInboxPolicy namespaces the published identity of an inbox
	// admission policy.
	DomainInboxPolicy = "tos.messaging.inbox-policy.v1\x00"
	// DomainDescriptorPolicy namespaces what an Agent commits its endpoint may
	// advertise.
	DomainDescriptorPolicy = "tos.messaging.descriptor-policy.v1\x00"
	// DomainRelaySet namespaces a published Mailbox Relay set.
	DomainRelaySet = "tos.messaging.relay-set.v1\x00"
	// DomainContactDescriptor namespaces a Messaging Contact Descriptor.
	DomainContactDescriptor = "tos.messaging.contact-descriptor.v1\x00"
	// DomainDHTLocator namespaces a published DHT locator.
	DomainDHTLocator = "tos.messaging.dht-locator.v1\x00"
	// DomainEventID namespaces the content-addressed Event identifier.
	DomainEventID = "tos.messaging.event-id.v1\x00"
	// DomainPrekeyBundle namespaces one published prekey bundle.
	DomainPrekeyBundle = "tos.messaging.prekey-bundle.v1\x00"
	// DomainPrekeyBundleSet namespaces a published device set.
	DomainPrekeyBundleSet = "tos.messaging.prekey-bundle-set.v1\x00"
	// DomainDeviceSession namespaces the session identifier a device pair
	// derives without negotiating.
	DomainDeviceSession = "tos.messaging.device-session.v1\x00"
	// DomainE2EEBinding namespaces the associated data of a ciphertext.
	DomainE2EEBinding = "tos.messaging.e2ee-binding.v1\x00"
	// DomainReachabilityTrial namespaces one measured trial record.
	DomainReachabilityTrial = "tos.messaging.reachability-trial.v1\x00"
	// DomainReachabilityPolicy namespaces a predeclared acceptance policy.
	DomainReachabilityPolicy = "tos.messaging.reachability-policy.v1\x00"
	// DomainReachabilityOperator namespaces the opaque operator derivation.
	DomainReachabilityOperator = "tos.messaging.reachability-operator.v1\x00"
	// DomainReachabilitySite namespaces the opaque site derivation.
	DomainReachabilitySite = "tos.messaging.reachability-site.v1\x00"
	// DomainReachabilityPairID namespaces the pair identifier derived from a
	// session. It is separate from the digest over a completed pair because
	// one domain must carry one meaning: reusing a separator across two object
	// kinds is signature confusion waiting for the field widths to change.
	DomainReachabilityPairID = "tos.messaging.reachability-pair-id.v1\x00"
	// DomainReachabilityPairResult namespaces the digest over the two halves
	// of one completed measurement.
	DomainReachabilityPairResult = "tos.messaging.reachability-pair-result.v1\x00"
	// DomainReachabilityCoordinator namespaces the coordinator identifier.
	DomainReachabilityCoordinator = "tos.messaging.reachability-coordinator.v1\x00"
	// DomainReachabilityObservation namespaces a coordinator attestation.
	DomainReachabilityObservation = "tos.messaging.reachability-observation.v1\x00"
	// DomainRoomMembership namespaces the digest a room commits over the members
	// of one epoch. The epoch is inside the preimage, so two epochs with the
	// same member set commit different digests and cannot be mistaken for each
	// other.
	DomainRoomMembership = "tos.messaging.room-membership.v1\x00"
)

// Domains is every separator in use. A new object appends to it, and the
// uniqueness test refuses a duplicate.
var Domains = []string{
	DomainEndpointDelegation,
	DomainEndpointID,
	DomainDescriptorPolicy,
	DomainRelaySet,
	DomainContactDescriptor,
	DomainDHTLocator,
	DomainEventID,
	DomainPrekeyBundle,
	DomainPrekeyBundleSet,
	DomainDeviceSession,
	DomainE2EEBinding,
	DomainReachabilityTrial,
	DomainReachabilityPolicy,
	DomainReachabilityOperator,
	DomainReachabilitySite,
	DomainReachabilityPairID,
	DomainReachabilityPairResult,
	DomainReachabilityCoordinator,
	DomainReachabilityObservation,
	DomainRoomMembership,
	DomainPayload,
	DomainInboxPolicy,
	DomainNegotiationRecord,
	DomainBudget,
	DomainNegotiationTerms,
	DomainOwnerDecision,
	DomainMandate,
	DomainAgentAction,
}
