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
	// DomainBudget namespaces the identifier of one asset's budget. This is the
	// optional global asset-risk ceiling; the per-mandate budget that carries a
	// mandate's MaxTotal has its own separator below. v2 folds the asset's
	// network into the preimage, so the same contract tuple on two networks is
	// two budgets rather than one shared ceiling.
	DomainBudget = "tos.messaging.budget.v2\x00"
	// DomainMandateBudget namespaces the identifier of one mandate's budget. It
	// is separate from DomainBudget because a mandate budget's preimage folds in
	// the mandate the ceiling belongs to, so two mandates over the same asset
	// derive different budgets and cannot draw on each other's total. v2 folds
	// the asset's network into the preimage, as DomainBudget does.
	DomainMandateBudget = "tos.messaging.mandate-budget.v2\x00"
	// DomainNegotiationTerms namespaces one set of agreed terms. v2 commits the
	// network identity -- the id and both genesis hashes, through the priced
	// asset -- so identical terms on two networks are two digests, and a
	// cross-network replay fails cryptographically rather than only at the
	// runtime binding check.
	DomainNegotiationTerms = "tos.messaging.negotiation-terms.v2\x00"
	// DomainOwnerDecision namespaces what an owner signs to authorise one
	// decision on their own interface.
	DomainOwnerDecision = "tos.messaging.owner-decision.v1\x00"
	// DomainMandate namespaces a standing authorisation the owner placed. v2
	// commits the network identity through the mandate's asset, so an
	// authorisation given for one network cannot be worn by another.
	DomainMandate = "tos.messaging.mandate.v2\x00"
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
	// DomainAdmissionInvite namespaces the private digest of a random one-time
	// inbox invitation. The bearer itself is never persisted.
	DomainAdmissionInvite = "tos.messaging.admission-invite.v1\x00"
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
	// DomainReachabilityTrial namespaces one measured trial record. v4 folds in
	// bounded sized-echo and segmented RLDP recovery results, so transport
	// evidence cannot be added, removed, reordered, or changed after signing.
	// It also retains the collector-manifest digests of both endpoints and the
	// phase-status booleans: a sidecar at the same orchestrator commit remains a
	// distinct implementation, and a failed phase cannot become unattempted.
	DomainReachabilityTrial = "tos.messaging.reachability-trial.v4\x00"
	// DomainReachabilityCollectorManifest namespaces the content-addressed
	// description of one collector build: orchestrator, ADNL implementation,
	// dependency version, binary hash, target, toolchain, and wire profile. The
	// digest over it is what a trial commits and what the two halves of a pair
	// cross-check about each other.
	DomainReachabilityCollectorManifest = "tos.messaging.reachability-collector-manifest.v1\x00"
	// DomainReachabilityPolicy namespaces a predeclared acceptance policy. v4
	// additionally folds in segmented RLDP and same-transfer recovery gates.
	DomainReachabilityPolicy = "tos.messaging.reachability-policy.v4\x00"
	// DomainReachabilityRLDPPayload derives deterministic, independently
	// reproducible bytes for the RLDP measurement response.
	DomainReachabilityRLDPPayload = "tos.messaging.reachability-rldp-payload.v1\x00"
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
	// DomainEconomicExecution namespaces the identity of one economic purchase,
	// independent of how any single action that would perform it is described.
	// Two actions that would buy the same thing under the same mandate share
	// this identity even when their summaries or provenance differ, which is
	// what makes a re-described purchase a repeat rather than a second spend.
	DomainEconomicExecution = "tos.messaging.economic-execution.v1\x00"
	// DomainRoomMembership namespaces the digest a room commits over the members
	// of one epoch. The epoch is inside the preimage, so two epochs with the
	// same member set commit different digests and cannot be mistaken for each
	// other.
	DomainRoomMembership = "tos.messaging.room-membership.v1\x00"
	// DomainRoomAuthorityTransfer namespaces the current authority Endpoint's
	// signature over one single-step room-authority transition.
	DomainRoomAuthorityTransfer = "tos.messaging.room-authority-transfer.v1\x00"
	// DomainRoomMembershipAuthorization namespaces the current authority's
	// signature over one founding or successor membership.
	DomainRoomMembershipAuthorization = "tos.messaging.room-membership-authorization.v1\x00"
	// DomainRoomRolePolicy namespaces the current room authority's bounded
	// assignment of elevated administrator and moderator powers.
	DomainRoomRolePolicy = "tos.messaging.room-role-policy.v1\x00"
	// DomainPublicChannelID namespaces a route-neutral public channel identity.
	DomainPublicChannelID = "tos.messaging.public-channel-id.v1\x00"
	// DomainPublicChannelProfile namespaces the authority-signed publisher and
	// moderator roster for one public-channel epoch.
	DomainPublicChannelProfile = "tos.messaging.public-channel-profile.v1\x00"
	// DomainPublicChannelEvent namespaces one publisher-signed public event.
	DomainPublicChannelEvent = "tos.messaging.public-channel-event.v1\x00"
	// DomainPublicChannelHistory namespaces a convergent complete event-set
	// commitment; transport arrival order is deliberately absent.
	DomainPublicChannelHistory = "tos.messaging.public-channel-history.v1\x00"
	// DomainStoredAck namespaces a Relay's durable-storage acknowledgement.
	// It is deliberately distinct from delivery and application ACK payloads:
	// a Relay storing ciphertext proves neither recipient nor runtime action.
	DomainStoredAck = "tos.messaging.stored-ack.v1\x00"
	// DomainConformanceReport namespaces an implementation's signed claim that
	// it consumed the committed positive and adversarial vector artifacts.
	DomainConformanceReport = "tos.messaging.conformance-report.v1\x00"
	// DomainMLSDeviceCredential namespaces the endpoint signature authorising
	// one device's distinct MLS leaf key and exact KeyPackage. v2 encodes both
	// genesis hashes as raw 32-byte values rather than display hex.
	DomainMLSDeviceCredential = "tos.messaging.mls-device-credential.v2\x00"
	// DomainMLSBasicCredential namespaces the opaque identity bytes carried by
	// the standard MLS BasicCredential.
	DomainMLSBasicCredential = "tos.messaging.mls-basic-credential.v1\x00"
	// DomainMLSGroupID namespaces the network-bound MLS group identifier.
	DomainMLSGroupID = "tos.messaging.mls-group-id.v1\x00"
	// DomainAttachmentMetadata commits plaintext metadata kept inside E2EE.
	DomainAttachmentMetadata = "tos.messaging.attachment-metadata.v1\x00"
	// DomainAttachmentChunk binds every AEAD chunk to its position and shape.
	DomainAttachmentChunk = "tos.messaging.attachment-chunk.v1\x00"
	// DomainAttachmentManifest identifies the ordered ciphertext chunk set.
	DomainAttachmentManifest = "tos.messaging.attachment-manifest.v1\x00"
	// DomainAgentPacketClaim namespaces a durable sender+nonce replay claim.
	DomainAgentPacketClaim = "tos.messaging.agent-packet-claim.v1\x00"
	// DomainMailboxCapabilityGrant namespaces one Endpoint-signed capability
	// key and its exact Relay, mailbox, operation and lifetime scope.
	DomainMailboxCapabilityGrant = "tos.messaging.mailbox-capability-grant.v1\x00"
	// DomainMailboxAccessRequest namespaces one capability-signed operation.
	DomainMailboxAccessRequest = "tos.messaging.mailbox-access-request.v1\x00"
	// DomainMailboxOperationBody namespaces the body digest a request signs.
	DomainMailboxOperationBody = "tos.messaging.mailbox-operation-body.v1\x00"
	// DomainMailboxAccessClaim namespaces the durable grant+nonce replay key.
	DomainMailboxAccessClaim = "tos.messaging.mailbox-access-claim.v1\x00"
	// DomainLabToken namespaces the hash of a local acceptance credential. It
	// is not a production authentication profile.
	DomainLabToken = "tos.messaging.lab.token.v1\x00"
	// DomainLabRoom namespaces a deterministic local acceptance room.
	DomainLabRoom = "tos.messaging.lab.room.v1\x00"
	// DomainLabMessage namespaces a local acceptance message identifier.
	DomainLabMessage = "tos.messaging.lab.message.v1\x00"
	// DomainOpenFoxMLSAAD binds a local encrypted acceptance message to the
	// exact room, authenticated sender, and retry-stable client identifier.
	DomainOpenFoxMLSAAD = "tos.messaging.openfox-mls-message-aad.v1\x00"
	// DomainOutboundIntent binds a runtime's semantic message and fixed route
	// independently of the daemon-owned creation time and Event ID.
	DomainOutboundIntent = "tos.messaging.outbound-intent.v1\x00"
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
	DomainReachabilityCollectorManifest,
	DomainReachabilityPolicy,
	DomainReachabilityRLDPPayload,
	DomainReachabilityOperator,
	DomainReachabilitySite,
	DomainReachabilityPairID,
	DomainReachabilityPairResult,
	DomainReachabilityCoordinator,
	DomainReachabilityObservation,
	DomainEconomicExecution,
	DomainRoomMembership,
	DomainRoomAuthorityTransfer,
	DomainRoomMembershipAuthorization,
	DomainRoomRolePolicy,
	DomainPublicChannelID,
	DomainPublicChannelProfile,
	DomainPublicChannelEvent,
	DomainPublicChannelHistory,
	DomainStoredAck,
	DomainConformanceReport,
	DomainMLSDeviceCredential,
	DomainMLSBasicCredential,
	DomainMLSGroupID,
	DomainAttachmentMetadata,
	DomainAttachmentChunk,
	DomainAttachmentManifest,
	DomainAgentPacketClaim,
	DomainMailboxCapabilityGrant,
	DomainMailboxAccessRequest,
	DomainMailboxOperationBody,
	DomainMailboxAccessClaim,
	DomainLabToken,
	DomainLabRoom,
	DomainLabMessage,
	DomainOpenFoxMLSAAD,
	DomainOutboundIntent,
	DomainPayload,
	DomainInboxPolicy,
	DomainAdmissionInvite,
	DomainNegotiationRecord,
	DomainBudget,
	DomainMandateBudget,
	DomainNegotiationTerms,
	DomainOwnerDecision,
	DomainMandate,
	DomainAgentAction,
}
