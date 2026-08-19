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
	// DomainE2EEBinding namespaces the associated data of a ciphertext.
	DomainE2EEBinding = "tos.messaging.e2ee-binding.v1\x00"
	// DomainReachabilityTrial namespaces one measured trial record.
	DomainReachabilityTrial = "tos.messaging.reachability-trial.v1\x00"
	// DomainReachabilityPolicy namespaces a predeclared acceptance policy.
	DomainReachabilityPolicy = "tos.messaging.reachability-policy.v1\x00"
	// DomainReachabilityOperator namespaces the opaque operator derivation.
	DomainReachabilityOperator = "tos.messaging.reachability-operator.v1\x00"
)

// Domains is every separator in use. A new object appends to it, and the
// uniqueness test refuses a duplicate.
var Domains = []string{
	DomainEndpointDelegation,
	DomainEndpointID,
	DomainContactDescriptor,
	DomainDHTLocator,
	DomainEventID,
	DomainPrekeyBundle,
	DomainPrekeyBundleSet,
	DomainE2EEBinding,
	DomainReachabilityTrial,
	DomainReachabilityPolicy,
	DomainReachabilityOperator,
}
