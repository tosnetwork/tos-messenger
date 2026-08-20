package e2ee

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sort"
)

// DefaultCandidateAlgorithmID names the concrete suite proposed for the M0
// freeze. Its presence does not freeze the value: the owner still has to
// ratify the decision package before this identifier becomes a wire promise.
const DefaultCandidateAlgorithmID = "tos.messaging.e2ee.x3dh-aes256gcm-dr.v1"

const (
	materialVersion = byte(1)
	stateVersion    = byte(1)
	headerVersion   = byte(1)

	publicMaterialBytes  = 1 + 32 + 32
	privateMaterialBytes = 1 + 32 + 32
	initialMessageBytes  = 1 + 32
	headerBytes          = 1 + 32 + 4 + 4

	maxSkippedKeys  = 1024
	maxSeenMessages = 1024
)

var (
	initialKDFLabel = []byte("x3dh-aes256gcm-dr initial root and chain")
	rootKDFLabel    = []byte("x3dh-aes256gcm-dr ratchet root and chain")
	messageKDFLabel = []byte("x3dh-aes256gcm-dr message key and nonce")
	stateMagic      = []byte("TSE2")
)

// NewDefaultSuite returns the route-independent one-to-one suite proposed by
// the decision package. The suite uses the operating system's cryptographic
// random source and keeps all mutable protocol state in the State values
// returned by its methods.
func NewDefaultSuite() Suite {
	return &doubleRatchetSuite{random: rand.Reader}
}

type doubleRatchetSuite struct {
	random io.Reader
}

func (s *doubleRatchetSuite) AlgorithmID() string { return DefaultCandidateAlgorithmID }

func (s *doubleRatchetSuite) NewPrekeyMaterial() ([]byte, []byte, error) {
	identity, err := generateX25519(s.random)
	if err != nil {
		return nil, nil, err
	}
	prekey, err := generateX25519(s.random)
	if err != nil {
		return nil, nil, err
	}
	public := append([]byte{materialVersion}, identity.PublicKey().Bytes()...)
	public = append(public, prekey.PublicKey().Bytes()...)
	secret := append([]byte{materialVersion}, identity.Bytes()...)
	secret = append(secret, prekey.Bytes()...)
	return public, secret, nil
}

func (s *doubleRatchetSuite) Initiate(private, peerPublic, binding []byte) (State, []byte, error) {
	local, err := parsePrivateMaterial(private)
	if err != nil {
		return nil, nil, err
	}
	peer, err := parsePublicMaterial(peerPublic)
	if err != nil {
		return nil, nil, err
	}
	self, err := generateX25519(s.random)
	if err != nil {
		return nil, nil, err
	}
	first, err := local.identity.ECDH(peer.prekey)
	if err != nil {
		return nil, nil, ErrNotAuthentic
	}
	second, err := self.ECDH(peer.identity)
	if err != nil {
		return nil, nil, ErrNotAuthentic
	}
	third, err := self.ECDH(peer.prekey)
	if err != nil {
		return nil, nil, ErrNotAuthentic
	}
	root, chain, err := deriveInitial(joinSecrets(first, second, third), binding)
	if err != nil {
		return nil, nil, err
	}
	state := ratchetState{
		root:        root,
		selfPrivate: array32(self.Bytes()),
		selfPublic:  array32(self.PublicKey().Bytes()),
		peerPublic:  array32(peer.prekey.Bytes()),
		sendChain:   chain,
		hasSend:     true,
	}
	encoded, err := encodeRatchetState(state)
	if err != nil {
		return nil, nil, err
	}
	initial := append([]byte{materialVersion}, self.PublicKey().Bytes()...)
	return encoded, initial, nil
}

func (s *doubleRatchetSuite) Accept(private, peerPublic, initial, binding []byte) (State, error) {
	local, err := parsePrivateMaterial(private)
	if err != nil {
		return nil, err
	}
	remote, err := parsePublicMaterial(peerPublic)
	if err != nil {
		return nil, err
	}
	peer, err := parseInitialMessage(initial)
	if err != nil {
		return nil, err
	}
	first, err := local.prekey.ECDH(remote.identity)
	if err != nil {
		return nil, ErrNotAuthentic
	}
	second, err := local.identity.ECDH(peer)
	if err != nil {
		return nil, ErrNotAuthentic
	}
	third, err := local.prekey.ECDH(peer)
	if err != nil {
		return nil, ErrNotAuthentic
	}
	root, chain, err := deriveInitial(joinSecrets(first, second, third), binding)
	if err != nil {
		return nil, err
	}
	state := ratchetState{
		root:         root,
		selfPrivate:  array32(local.prekey.Bytes()),
		selfPublic:   array32(local.prekey.PublicKey().Bytes()),
		peerPublic:   array32(peer.Bytes()),
		receiveChain: chain,
		hasReceive:   true,
	}
	return encodeRatchetState(state)
}

func (s *doubleRatchetSuite) Seal(raw State, plaintext, binding []byte) ([]byte, State, error) {
	state, err := decodeRatchetState(raw)
	if err != nil {
		return nil, nil, err
	}
	if !state.hasSend {
		if err := s.advanceSendingRatchet(&state); err != nil {
			return nil, nil, err
		}
	}
	if state.sendNumber == ^uint32(0) {
		return nil, nil, ErrSessionExpired
	}
	header := encodeHeader(messageHeader{
		public:         state.selfPublic,
		previousNumber: state.previousSendNumber,
		number:         state.sendNumber,
	})
	messageKey, nextChain := advanceChain(state.sendChain)
	aead, nonce, err := messageAEAD(messageKey)
	if err != nil {
		return nil, nil, err
	}
	additional := append(append([]byte(nil), header...), binding...)
	ciphertext := append(header, aead.Seal(nil, nonce, plaintext, additional)...)
	state.sendChain = nextChain
	state.sendNumber++
	next, err := encodeRatchetState(state)
	if err != nil {
		return nil, nil, err
	}
	return ciphertext, next, nil
}

func (s *doubleRatchetSuite) Open(raw State, ciphertext, binding []byte) ([]byte, State, error) {
	state, err := decodeRatchetState(raw)
	if err != nil {
		return nil, nil, err
	}
	digest := sha256.Sum256(ciphertext)
	if state.hasSeen(digest) {
		return nil, nil, ErrReplayed
	}
	header, body, err := decodeHeader(ciphertext)
	if err != nil {
		return nil, nil, ErrNotAuthentic
	}
	additional := append(append([]byte(nil), ciphertext[:headerBytes]...), binding...)
	if key, found := state.takeSkipped(header.public, header.number); found {
		plaintext, err := openMessage(key, body, additional)
		if err != nil {
			return nil, nil, ErrNotAuthentic
		}
		state.remember(digest)
		next, err := encodeRatchetState(state)
		if err != nil {
			return nil, nil, err
		}
		return plaintext, next, nil
	}
	if header.public != state.peerPublic {
		if err := state.skipTo(header.previousNumber); err != nil {
			return nil, nil, err
		}
		if err := s.advanceReceivingRatchet(&state, header.public); err != nil {
			return nil, nil, ErrNotAuthentic
		}
	}
	if header.number < state.receiveNumber {
		return nil, nil, ErrReplayed
	}
	if err := state.skipTo(header.number); err != nil {
		return nil, nil, err
	}
	if !state.hasReceive {
		return nil, nil, ErrNotAuthentic
	}
	messageKey, nextChain := advanceChain(state.receiveChain)
	plaintext, err := openMessage(messageKey, body, additional)
	if err != nil {
		return nil, nil, ErrNotAuthentic
	}
	state.receiveChain = nextChain
	state.receiveNumber++
	state.remember(digest)
	next, err := encodeRatchetState(state)
	if err != nil {
		return nil, nil, err
	}
	return plaintext, next, nil
}

func (s *doubleRatchetSuite) KeyMaterial(raw State) (State, error) {
	state, err := decodeRatchetState(raw)
	if err != nil {
		return nil, err
	}
	state.seen = nil
	return encodeRatchetState(state)
}

func (s *doubleRatchetSuite) advanceSendingRatchet(state *ratchetState) error {
	peer, err := ecdh.X25519().NewPublicKey(state.peerPublic[:])
	if err != nil {
		return err
	}
	self, err := generateX25519(s.random)
	if err != nil {
		return err
	}
	shared, err := self.ECDH(peer)
	if err != nil {
		return err
	}
	root, chain, err := deriveRoot(state.root, shared)
	if err != nil {
		return err
	}
	state.previousSendNumber = state.sendNumber
	state.sendNumber = 0
	state.root = root
	state.sendChain = chain
	state.hasSend = true
	state.selfPrivate = array32(self.Bytes())
	state.selfPublic = array32(self.PublicKey().Bytes())
	return nil
}

func (s *doubleRatchetSuite) advanceReceivingRatchet(state *ratchetState, public [32]byte) error {
	self, err := ecdh.X25519().NewPrivateKey(state.selfPrivate[:])
	if err != nil {
		return err
	}
	peer, err := ecdh.X25519().NewPublicKey(public[:])
	if err != nil {
		return err
	}
	shared, err := self.ECDH(peer)
	if err != nil {
		return err
	}
	root, chain, err := deriveRoot(state.root, shared)
	if err != nil {
		return err
	}
	state.root = root
	state.receiveChain = chain
	state.hasReceive = true
	state.peerPublic = public
	state.receiveNumber = 0
	state.hasSend = false
	state.sendChain = [32]byte{}
	return nil
}

type messageHeader struct {
	public         [32]byte
	previousNumber uint32
	number         uint32
}

func encodeHeader(header messageHeader) []byte {
	encoded := make([]byte, headerBytes)
	encoded[0] = headerVersion
	copy(encoded[1:33], header.public[:])
	binary.BigEndian.PutUint32(encoded[33:37], header.previousNumber)
	binary.BigEndian.PutUint32(encoded[37:41], header.number)
	return encoded
}

func decodeHeader(ciphertext []byte) (messageHeader, []byte, error) {
	if len(ciphertext) < headerBytes+16 || ciphertext[0] != headerVersion {
		return messageHeader{}, nil, ErrNotAuthentic
	}
	header := messageHeader{
		public:         array32(ciphertext[1:33]),
		previousNumber: binary.BigEndian.Uint32(ciphertext[33:37]),
		number:         binary.BigEndian.Uint32(ciphertext[37:41]),
	}
	return header, ciphertext[headerBytes:], nil
}

func deriveInitial(shared, binding []byte) ([32]byte, [32]byte, error) {
	salt := sha256.Sum256(append(append([]byte(nil), initialKDFLabel...), binding...))
	derived, err := hkdf.Key(sha256.New, shared, salt[:], string(initialKDFLabel), 64)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	return array32(derived[:32]), array32(derived[32:]), nil
}

func deriveRoot(root [32]byte, shared []byte) ([32]byte, [32]byte, error) {
	derived, err := hkdf.Key(sha256.New, shared, root[:], string(rootKDFLabel), 64)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	return array32(derived[:32]), array32(derived[32:]), nil
}

func advanceChain(chain [32]byte) ([32]byte, [32]byte) {
	messageMAC := hmac.New(sha256.New, chain[:])
	messageMAC.Write([]byte{1})
	message := array32(messageMAC.Sum(nil))
	nextMAC := hmac.New(sha256.New, chain[:])
	nextMAC.Write([]byte{2})
	next := array32(nextMAC.Sum(nil))
	return message, next
}

func messageAEAD(messageKey [32]byte) (cipher.AEAD, []byte, error) {
	material, err := hkdf.Key(sha256.New, messageKey[:], nil, string(messageKDFLabel), 44)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(material[:32])
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	return aead, material[32:], nil
}

func openMessage(messageKey [32]byte, ciphertext, additional []byte) ([]byte, error) {
	aead, nonce, err := messageAEAD(messageKey)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, additional)
}

type publicPrekeyMaterial struct {
	identity *ecdh.PublicKey
	prekey   *ecdh.PublicKey
}

type privatePrekeyMaterial struct {
	identity *ecdh.PrivateKey
	prekey   *ecdh.PrivateKey
}

func parsePublicMaterial(material []byte) (publicPrekeyMaterial, error) {
	if len(material) != publicMaterialBytes || material[0] != materialVersion {
		return publicPrekeyMaterial{}, errors.New("prekey public material is unusable")
	}
	identity, err := ecdh.X25519().NewPublicKey(material[1:33])
	if err != nil {
		return publicPrekeyMaterial{}, errors.New("prekey public material is unusable")
	}
	prekey, err := ecdh.X25519().NewPublicKey(material[33:])
	if err != nil {
		return publicPrekeyMaterial{}, errors.New("prekey public material is unusable")
	}
	return publicPrekeyMaterial{identity: identity, prekey: prekey}, nil
}

func parsePrivateMaterial(material []byte) (privatePrekeyMaterial, error) {
	if len(material) != privateMaterialBytes || material[0] != materialVersion {
		return privatePrekeyMaterial{}, errors.New("prekey private material is unusable")
	}
	identity, err := ecdh.X25519().NewPrivateKey(material[1:33])
	if err != nil {
		return privatePrekeyMaterial{}, errors.New("prekey private material is unusable")
	}
	prekey, err := ecdh.X25519().NewPrivateKey(material[33:])
	if err != nil {
		return privatePrekeyMaterial{}, errors.New("prekey private material is unusable")
	}
	return privatePrekeyMaterial{identity: identity, prekey: prekey}, nil
}

func parseInitialMessage(initial []byte) (*ecdh.PublicKey, error) {
	if len(initial) != initialMessageBytes || initial[0] != materialVersion {
		return nil, errors.New("initial message is unusable")
	}
	public, err := ecdh.X25519().NewPublicKey(initial[1:])
	if err != nil {
		return nil, errors.New("initial message is unusable")
	}
	return public, nil
}

func generateX25519(random io.Reader) (*ecdh.PrivateKey, error) {
	private := make([]byte, 32)
	if _, err := io.ReadFull(random, private); err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPrivateKey(private)
}

func joinSecrets(secrets ...[]byte) []byte {
	joined := make([]byte, 0, 32*len(secrets))
	for _, secret := range secrets {
		joined = append(joined, secret...)
	}
	return joined
}

type skippedKey struct {
	public [32]byte
	number uint32
	key    [32]byte
}

type ratchetState struct {
	root               [32]byte
	selfPrivate        [32]byte
	selfPublic         [32]byte
	peerPublic         [32]byte
	sendChain          [32]byte
	receiveChain       [32]byte
	hasSend            bool
	hasReceive         bool
	sendNumber         uint32
	receiveNumber      uint32
	previousSendNumber uint32
	skipped            []skippedKey
	seen               [][32]byte
}

func (s *ratchetState) skipTo(number uint32) error {
	if number < s.receiveNumber {
		return ErrReplayed
	}
	gap := uint64(number) - uint64(s.receiveNumber)
	if gap > maxSkippedKeys || uint64(len(s.skipped))+gap > maxSkippedKeys {
		return errors.New("message is beyond the skipped-key bound")
	}
	if gap > 0 && !s.hasReceive {
		return ErrNotAuthentic
	}
	for s.receiveNumber < number {
		key, next := advanceChain(s.receiveChain)
		s.skipped = append(s.skipped, skippedKey{public: s.peerPublic, number: s.receiveNumber, key: key})
		s.receiveChain = next
		s.receiveNumber++
	}
	return nil
}

func (s *ratchetState) takeSkipped(public [32]byte, number uint32) ([32]byte, bool) {
	for index, skipped := range s.skipped {
		if skipped.public == public && skipped.number == number {
			s.skipped = append(s.skipped[:index], s.skipped[index+1:]...)
			return skipped.key, true
		}
	}
	return [32]byte{}, false
}

func (s *ratchetState) hasSeen(digest [32]byte) bool {
	for _, seen := range s.seen {
		if hmac.Equal(seen[:], digest[:]) {
			return true
		}
	}
	return false
}

func (s *ratchetState) remember(digest [32]byte) {
	if len(s.seen) == maxSeenMessages {
		copy(s.seen, s.seen[1:])
		s.seen[len(s.seen)-1] = digest
		return
	}
	s.seen = append(s.seen, digest)
}

func encodeRatchetState(state ratchetState) (State, error) {
	if len(state.skipped) > maxSkippedKeys || len(state.seen) > maxSeenMessages {
		return nil, ErrStateUnusable
	}
	sort.Slice(state.skipped, func(i, j int) bool {
		if compared := bytes.Compare(state.skipped[i].public[:], state.skipped[j].public[:]); compared != 0 {
			return compared < 0
		}
		return state.skipped[i].number < state.skipped[j].number
	})
	encoded := make([]byte, 0, 4+1+32*6+2+12+2+len(state.skipped)*68+2+len(state.seen)*32)
	encoded = append(encoded, stateMagic...)
	encoded = append(encoded, stateVersion)
	encoded = append(encoded, state.root[:]...)
	encoded = append(encoded, state.selfPrivate[:]...)
	encoded = append(encoded, state.selfPublic[:]...)
	encoded = append(encoded, state.peerPublic[:]...)
	encoded = append(encoded, state.sendChain[:]...)
	encoded = append(encoded, state.receiveChain[:]...)
	flags := byte(0)
	if state.hasSend {
		flags |= 1
	}
	if state.hasReceive {
		flags |= 2
	}
	encoded = append(encoded, flags)
	encoded = binary.BigEndian.AppendUint32(encoded, state.sendNumber)
	encoded = binary.BigEndian.AppendUint32(encoded, state.receiveNumber)
	encoded = binary.BigEndian.AppendUint32(encoded, state.previousSendNumber)
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(state.skipped)))
	for _, skipped := range state.skipped {
		encoded = append(encoded, skipped.public[:]...)
		encoded = binary.BigEndian.AppendUint32(encoded, skipped.number)
		encoded = append(encoded, skipped.key[:]...)
	}
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(state.seen)))
	for _, seen := range state.seen {
		encoded = append(encoded, seen[:]...)
	}
	if err := ValidateState(encoded); err != nil {
		return nil, err
	}
	return encoded, nil
}

func decodeRatchetState(raw State) (ratchetState, error) {
	if err := ValidateState(raw); err != nil {
		return ratchetState{}, err
	}
	reader := bytes.NewReader(raw)
	magic := make([]byte, len(stateMagic))
	if _, err := io.ReadFull(reader, magic); err != nil || !bytes.Equal(magic, stateMagic) {
		return ratchetState{}, ErrStateUnusable
	}
	version, err := reader.ReadByte()
	if err != nil || version != stateVersion {
		return ratchetState{}, ErrStateUnusable
	}
	state := ratchetState{}
	fields := []*[32]byte{&state.root, &state.selfPrivate, &state.selfPublic, &state.peerPublic, &state.sendChain, &state.receiveChain}
	for _, field := range fields {
		if _, err := io.ReadFull(reader, field[:]); err != nil {
			return ratchetState{}, ErrStateUnusable
		}
	}
	flags, err := reader.ReadByte()
	if err != nil || flags&^byte(3) != 0 {
		return ratchetState{}, ErrStateUnusable
	}
	state.hasSend = flags&1 != 0
	state.hasReceive = flags&2 != 0
	if err := binary.Read(reader, binary.BigEndian, &state.sendNumber); err != nil {
		return ratchetState{}, ErrStateUnusable
	}
	if err := binary.Read(reader, binary.BigEndian, &state.receiveNumber); err != nil {
		return ratchetState{}, ErrStateUnusable
	}
	if err := binary.Read(reader, binary.BigEndian, &state.previousSendNumber); err != nil {
		return ratchetState{}, ErrStateUnusable
	}
	var skippedCount uint16
	if err := binary.Read(reader, binary.BigEndian, &skippedCount); err != nil || skippedCount > maxSkippedKeys {
		return ratchetState{}, ErrStateUnusable
	}
	state.skipped = make([]skippedKey, int(skippedCount))
	for index := range state.skipped {
		if _, err := io.ReadFull(reader, state.skipped[index].public[:]); err != nil {
			return ratchetState{}, ErrStateUnusable
		}
		if err := binary.Read(reader, binary.BigEndian, &state.skipped[index].number); err != nil {
			return ratchetState{}, ErrStateUnusable
		}
		if _, err := io.ReadFull(reader, state.skipped[index].key[:]); err != nil {
			return ratchetState{}, ErrStateUnusable
		}
	}
	var seenCount uint16
	if err := binary.Read(reader, binary.BigEndian, &seenCount); err != nil || seenCount > maxSeenMessages {
		return ratchetState{}, ErrStateUnusable
	}
	state.seen = make([][32]byte, int(seenCount))
	seenDigests := make(map[[32]byte]struct{}, len(state.seen))
	for index := range state.seen {
		if _, err := io.ReadFull(reader, state.seen[index][:]); err != nil {
			return ratchetState{}, ErrStateUnusable
		}
		if _, duplicate := seenDigests[state.seen[index]]; duplicate {
			return ratchetState{}, ErrStateUnusable
		}
		seenDigests[state.seen[index]] = struct{}{}
	}
	if reader.Len() != 0 {
		return ratchetState{}, ErrStateUnusable
	}
	private, err := ecdh.X25519().NewPrivateKey(state.selfPrivate[:])
	if err != nil || !bytes.Equal(private.PublicKey().Bytes(), state.selfPublic[:]) {
		return ratchetState{}, ErrStateUnusable
	}
	if _, err := ecdh.X25519().NewPublicKey(state.peerPublic[:]); err != nil {
		return ratchetState{}, ErrStateUnusable
	}
	if (!state.hasSend && state.sendChain != [32]byte{}) ||
		(!state.hasReceive && state.receiveChain != [32]byte{}) {
		return ratchetState{}, ErrStateUnusable
	}
	type skippedIdentity struct {
		public [32]byte
		number uint32
	}
	skippedIdentities := make(map[skippedIdentity]struct{}, len(state.skipped))
	for _, skipped := range state.skipped {
		identity := skippedIdentity{public: skipped.public, number: skipped.number}
		if _, duplicate := skippedIdentities[identity]; duplicate {
			return ratchetState{}, ErrStateUnusable
		}
		skippedIdentities[identity] = struct{}{}
	}
	return state, nil
}

func array32(value []byte) [32]byte {
	var out [32]byte
	copy(out[:], value)
	return out
}
