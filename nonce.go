package shadowfax

import (
	"crypto/rand"
	"io"

	"gopkg.in/basen.v1"
	"gopkg.in/errgo.v1"
)

// Nonce is a 24-byte number that should be used once per message.
type Nonce [24]byte

// DecodeNonce decodes a nonce from its Base58 string representation.
func DecodeNonce(s string) (*Nonce, error) {
	var nonce Nonce
	buf, err := basen.Base58.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(buf) != 24 {
		return nil, errgo.Newf("invalid nonce length %q", len(buf))
	}
	copy(nonce[:], buf)
	return &nonce, nil
}

// Encode encodes the nonce to a Base58 string representation.
func (n Nonce) Encode() string {
	return basen.Base58.EncodeToString(n[:])
}

// NewNonce returns a new random nonce.
func NewNonce() (*Nonce, error) {
	n := new(Nonce)
	_, err := io.ReadFull(rand.Reader, n[:])
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return n, nil
}
