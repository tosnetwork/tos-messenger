package directory

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
)

func signEndpoint(signer crypto.Signer, preimage []byte) ([]byte, error) {
	if signer == nil {
		return nil, errors.New("no Endpoint signer")
	}
	public, ok := signer.Public().(ed25519.PublicKey)
	if !ok || len(public) != ed25519.PublicKeySize {
		return nil, errors.New("Endpoint signer is not Ed25519")
	}
	signature, err := signer.Sign(rand.Reader, preimage, crypto.Hash(0))
	if err != nil {
		return nil, errors.New("Endpoint signer failed")
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(public, preimage, signature) {
		return nil, errors.New("Endpoint signer returned an invalid signature")
	}
	return append([]byte(nil), signature...), nil
}
