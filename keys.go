package shadowfax

import (
	"crypto/rand"

	"golang.org/x/crypto/nacl/box"
	"gopkg.in/basen.v1"
	"gopkg.in/errgo.v1"
)

// PublicKey is an ed25519 public key.
type PublicKey [32]byte

// PrivateKey is an ed25519 private key.
type PrivateKey [32]byte

// KeyPair holds a public and private key for asymmetric box crypto.
type KeyPair struct {
	PublicKey  *PublicKey
	PrivateKey *PrivateKey
}

// NewKeyPair returns a new KeyPair.
func NewKeyPair() (KeyPair, error) {
	fail := KeyPair{nil, nil}
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return fail, errgo.NoteMask(err, "failed to generate key")
	}
	return KeyPair{(*PublicKey)(pub), (*PrivateKey)(priv)}, nil
}

// DecodePublicKey decodes a public key from its Base58 string representation.
func DecodePublicKey(s string) (*PublicKey, error) {
	var publicKey PublicKey
	buf, err := basen.Base58.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(buf) != 32 {
		return nil, errgo.Newf("invalid key length %q", len(buf))
	}
	copy(publicKey[:], buf)
	return &publicKey, nil
}

// Encode encodes the public key to a Base58 string representation.
func (pk PublicKey) Encode() string {
	return basen.Base58.EncodeToString(pk[:])
}
