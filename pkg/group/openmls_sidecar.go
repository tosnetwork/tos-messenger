package group

// This file is the process-isolated Go adapter for the pinned OpenMLS Rust
// implementation in rust/openmls-driver. The sidecar receives one bounded
// request and exits. It cannot retain authority between calls: every successful
// operation returns the complete next state for atomic journaling.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

const (
	OpenMLSSidecarSchema    = "tos.openmls.sidecar.v1"
	MaxOpenMLSSidecarReply  = 4 << 20
	MaxOpenMLSStateBytes    = 512 << 10
	MaxOpenMLSMessageBytes  = 1 << 20
	DefaultOpenMLSTimeout   = 10 * time.Second
	MaxOpenMLSIdentityBytes = 4096
)

type OpenMLSIdentity struct {
	State                  []byte
	LeafSignaturePublicKey ed25519.PublicKey
	KeyPackage             []byte
}

type OpenMLSSidecar struct {
	// Command contains the executable and optional fixed arguments. Fixed
	// arguments make the boundary testable without a shell.
	Command []string
	Timeout time.Duration
}

type openMLSRequest struct {
	Schema           string   `json:"schema"`
	Operation        string   `json:"op"`
	State            string   `json:"state,omitempty"`
	Identity         string   `json:"identity,omitempty"`
	PublicKey        string   `json:"public_key,omitempty"`
	GroupID          string   `json:"group_id,omitempty"`
	KeyPackage       string   `json:"key_package,omitempty"`
	KeyPackages      []string `json:"key_packages,omitempty"`
	RemoveIdentities []string `json:"remove_identities,omitempty"`
	Welcome          string   `json:"welcome,omitempty"`
	Message          string   `json:"message,omitempty"`
	AAD              string   `json:"aad,omitempty"`
	Plaintext        string   `json:"plaintext,omitempty"`
}

type openMLSResponse struct {
	Schema     string  `json:"schema"`
	OK         bool    `json:"ok"`
	Error      string  `json:"error,omitempty"`
	State      string  `json:"state,omitempty"`
	PublicKey  string  `json:"public_key,omitempty"`
	KeyPackage string  `json:"key_package,omitempty"`
	Commit     string  `json:"commit,omitempty"`
	Welcome    string  `json:"welcome,omitempty"`
	Message    string  `json:"message,omitempty"`
	Plaintext  string  `json:"plaintext,omitempty"`
	GroupID    string  `json:"group_id,omitempty"`
	Epoch      *uint64 `json:"epoch,omitempty"`
}

func (d *OpenMLSSidecar) CipherSuite() uint16 { return MLSCipherSuite }

func (d *OpenMLSSidecar) Inspect(state []byte) (MLSStateInfo, error) {
	response, err := d.call(openMLSRequest{Operation: "inspect", State: b64(state)})
	if err != nil {
		return MLSStateInfo{}, err
	}
	groupID, err := decodeOpenMLS("group id", response.GroupID, 255)
	if err != nil || response.Epoch == nil {
		return MLSStateInfo{}, errors.New("invalid OpenMLS state binding")
	}
	return MLSStateInfo{GroupID: groupID, Epoch: *response.Epoch}, nil
}

func (d *OpenMLSSidecar) NewIdentity(identity []byte) (OpenMLSIdentity, error) {
	if len(identity) == 0 || len(identity) > MaxOpenMLSIdentityBytes {
		return OpenMLSIdentity{}, errors.New("invalid MLS BasicCredential identity")
	}
	response, err := d.call(openMLSRequest{Operation: "identity", Identity: b64(identity)})
	if err != nil {
		return OpenMLSIdentity{}, err
	}
	state, err := decodeOpenMLS("state", response.State, MaxOpenMLSStateBytes)
	if err != nil {
		return OpenMLSIdentity{}, err
	}
	publicKey, err := decodeOpenMLS("public key", response.PublicKey, ed25519.PublicKeySize)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return OpenMLSIdentity{}, errors.New("invalid OpenMLS leaf public key")
	}
	keyPackage, err := decodeOpenMLS("KeyPackage", response.KeyPackage, MaxKeyPackageBytes)
	if err != nil {
		return OpenMLSIdentity{}, err
	}
	return OpenMLSIdentity{State: state, LeafSignaturePublicKey: ed25519.PublicKey(publicKey), KeyPackage: keyPackage}, nil
}

func (d *OpenMLSSidecar) CreateGroup(identityState, ownKeyPackage, groupID []byte) ([]byte, error) {
	response, err := d.call(openMLSRequest{Operation: "create", State: b64(identityState), KeyPackage: b64(ownKeyPackage), GroupID: b64(groupID)})
	if err != nil {
		return nil, err
	}
	return decodeOpenMLS("state", response.State, MaxOpenMLSStateBytes)
}

func (d *OpenMLSSidecar) ValidateKeyPackage(keyPackage, expectedIdentity []byte, expectedKey ed25519.PublicKey) error {
	if len(keyPackage) == 0 || len(keyPackage) > MaxKeyPackageBytes || len(expectedIdentity) == 0 || len(expectedIdentity) > MaxOpenMLSIdentityBytes || len(expectedKey) != ed25519.PublicKeySize {
		return errors.New("invalid OpenMLS KeyPackage validation input")
	}
	_, err := d.call(openMLSRequest{Operation: "validate", KeyPackage: b64(keyPackage), Identity: b64(expectedIdentity), PublicKey: b64(expectedKey)})
	return err
}

func (d *OpenMLSSidecar) Join(identityState, welcome []byte) ([]byte, error) {
	response, err := d.call(openMLSRequest{Operation: "join", State: b64(identityState), Welcome: b64(welcome)})
	if err != nil {
		return nil, err
	}
	return decodeOpenMLS("state", response.State, MaxOpenMLSStateBytes)
}

func (d *OpenMLSSidecar) Commit(state []byte, operations []LeafOperation) ([]byte, []byte, map[string][]byte, error) {
	if len(operations) == 0 || len(operations) > 64 {
		return nil, nil, nil, errors.New("invalid MLS leaf operation count")
	}
	packages := make([]string, 0, len(operations))
	removals := make([]string, 0, len(operations))
	refs := make([]string, 0, len(operations))
	for _, operation := range operations {
		switch operation.Kind {
		case LeafAdd:
			if operation.Prior != nil || !validOpenMLSNextLeaf(operation.Next) {
				return nil, nil, nil, errors.New("invalid OpenMLS add operation")
			}
			if err := d.ValidateKeyPackage(operation.Next.KeyPackage, operation.Next.CredentialIdentity, operation.Next.LeafSignaturePublicKey); err != nil {
				return nil, nil, nil, err
			}
			packages = append(packages, b64(operation.Next.KeyPackage))
			refs = append(refs, operation.Next.KeyPackageRef)
		case LeafRemove:
			if operation.Next != nil || !validOpenMLSPriorLeaf(operation.Prior) {
				return nil, nil, nil, errors.New("invalid OpenMLS remove operation")
			}
			removals = append(removals, b64(operation.Prior.CredentialIdentity))
		case LeafUpdate:
			if !validOpenMLSPriorLeaf(operation.Prior) || !validOpenMLSNextLeaf(operation.Next) || bytes.Equal(operation.Prior.CredentialIdentity, operation.Next.CredentialIdentity) {
				return nil, nil, nil, errors.New("invalid OpenMLS update operation")
			}
			if err := d.ValidateKeyPackage(operation.Next.KeyPackage, operation.Next.CredentialIdentity, operation.Next.LeafSignaturePublicKey); err != nil {
				return nil, nil, nil, err
			}
			removals = append(removals, b64(operation.Prior.CredentialIdentity))
			packages = append(packages, b64(operation.Next.KeyPackage))
			refs = append(refs, operation.Next.KeyPackageRef)
		default:
			return nil, nil, nil, errors.New("unsupported OpenMLS leaf operation")
		}
	}
	response, err := d.call(openMLSRequest{Operation: "commit", State: b64(state), KeyPackages: packages, RemoveIdentities: removals})
	if err != nil {
		return nil, nil, nil, err
	}
	next, err := decodeOpenMLS("state", response.State, MaxOpenMLSStateBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	commit, err := decodeOpenMLS("commit", response.Commit, MaxOpenMLSMessageBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	welcomes := make(map[string][]byte, len(refs))
	if len(refs) > 0 {
		welcome, err := decodeOpenMLS("Welcome", response.Welcome, MaxOpenMLSMessageBytes)
		if err != nil {
			return nil, nil, nil, err
		}
		for _, ref := range refs {
			welcomes[ref] = append([]byte(nil), welcome...)
		}
	}
	return next, commit, welcomes, nil
}

func validOpenMLSPriorLeaf(leaf *Leaf) bool {
	return leaf != nil && len(leaf.CredentialIdentity) > 0 && len(leaf.CredentialIdentity) <= MaxOpenMLSIdentityBytes
}

func validOpenMLSNextLeaf(leaf *Leaf) bool {
	return validOpenMLSPriorLeaf(leaf) && len(leaf.LeafSignaturePublicKey) == ed25519.PublicKeySize && canon.ValidDigest(leaf.KeyPackageRef) && len(leaf.KeyPackage) > 0 && len(leaf.KeyPackage) <= MaxKeyPackageBytes
}

func (d *OpenMLSSidecar) Apply(state, commit []byte) ([]byte, error) {
	response, err := d.call(openMLSRequest{Operation: "apply", State: b64(state), Message: b64(commit)})
	if err != nil {
		return nil, err
	}
	return decodeOpenMLS("state", response.State, MaxOpenMLSStateBytes)
}

func (d *OpenMLSSidecar) Seal(state, aad, plaintext []byte) ([]byte, []byte, error) {
	response, err := d.call(openMLSRequest{Operation: "seal", State: b64(state), AAD: optionalB64(aad), Plaintext: b64(plaintext)})
	if err != nil {
		return nil, nil, err
	}
	next, err := decodeOpenMLS("state", response.State, MaxOpenMLSStateBytes)
	if err != nil {
		return nil, nil, err
	}
	message, err := decodeOpenMLS("private message", response.Message, MaxOpenMLSMessageBytes)
	return next, message, err
}

func (d *OpenMLSSidecar) Open(state, aad, message []byte) ([]byte, []byte, error) {
	response, err := d.call(openMLSRequest{Operation: "open", State: b64(state), AAD: optionalB64(aad), Message: b64(message)})
	if err != nil {
		return nil, nil, err
	}
	next, err := decodeOpenMLS("state", response.State, MaxOpenMLSStateBytes)
	if err != nil {
		return nil, nil, err
	}
	plaintext, err := decodeOpenMLS("plaintext", response.Plaintext, MaxOpenMLSMessageBytes)
	return next, plaintext, err
}

func (d *OpenMLSSidecar) call(request openMLSRequest) (openMLSResponse, error) {
	if d == nil || len(d.Command) == 0 || d.Command[0] == "" {
		return openMLSResponse{}, errors.New("no OpenMLS sidecar command")
	}
	request.Schema = OpenMLSSidecarSchema
	raw, err := json.Marshal(request)
	if err != nil || len(raw) > MaxOpenMLSSidecarReply {
		return openMLSResponse{}, errors.New("invalid OpenMLS sidecar request")
	}
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = DefaultOpenMLSTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, d.Command[0], d.Command[1:]...)
	command.Stdin = bytes.NewReader(raw)
	stdout := &limitedBuffer{remaining: MaxOpenMLSSidecarReply}
	stderr := &limitedBuffer{remaining: 4096}
	command.Stdout, command.Stderr = stdout, stderr
	runErr := command.Run()
	if ctx.Err() != nil {
		return openMLSResponse{}, errors.New("OpenMLS sidecar timed out")
	}
	if stdout.exceeded {
		return openMLSResponse{}, errors.New("OpenMLS sidecar response exceeds bound")
	}
	var response openMLSResponse
	decoder := json.NewDecoder(bytes.NewReader(stdout.bytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return openMLSResponse{}, errors.New("invalid OpenMLS sidecar response")
	}
	if err := ensureJSONEOF(decoder); err != nil || response.Schema != OpenMLSSidecarSchema {
		return openMLSResponse{}, errors.New("invalid OpenMLS sidecar response binding")
	}
	if runErr != nil || !response.OK {
		if response.Error == "" {
			response.Error = "operation failed"
		}
		return openMLSResponse{}, fmt.Errorf("OpenMLS sidecar: %s", response.Error)
	}
	return response, nil
}

type limitedBuffer struct {
	bytes     []byte
	remaining int
	exceeded  bool
}

func (w *limitedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	if len(value) > w.remaining {
		value = value[:w.remaining]
		w.exceeded = true
	}
	w.bytes = append(w.bytes, value...)
	w.remaining -= len(value)
	return original, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func b64(value []byte) string { return base64.StdEncoding.EncodeToString(value) }
func optionalB64(value []byte) string {
	if len(value) == 0 {
		return ""
	}
	return b64(value)
}

func decodeOpenMLS(label, value string, max int) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) == 0 || len(decoded) > max {
		return nil, fmt.Errorf("invalid OpenMLS %s", label)
	}
	return decoded, nil
}

var _ Driver = (*OpenMLSSidecar)(nil)
var _ StateInspector = (*OpenMLSSidecar)(nil)
