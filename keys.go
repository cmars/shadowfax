/*
  Copyright 2015 Casey Marshall.

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

package shadowfax

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/nacl/box"
	"gopkg.in/basen.v1"
	"gopkg.in/errgo.v1"
)

// PublicKey is a curve25519 public key.
type PublicKey [32]byte

// PrivateKey is a curve25519 private key.
type PrivateKey [32]byte

// SecretKey is a secret key used for symmetric encryption.
type SecretKey [32]byte

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

// NewSecretKey returns a new randomly-generated secret key.
func NewSecretKey() (*SecretKey, error) {
	var key SecretKey
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return &key, nil
}
