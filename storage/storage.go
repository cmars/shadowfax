/*
  Copyright 2015 Casey Marshall.

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

package storage

import (
	sf "github.com/cmars/shadowfax"
)

// Contacts organizes public keys by a locally assigned name.
type Contacts interface {

	// Key returns the latest public key for the given name.
	Key(name string) (*sf.PublicKey, error)

	// Name returns the latest name given to the public key.
	Name(key *sf.PublicKey) (string, error)

	// Put assigns a public key to a given name, superseding any prior name
	// assignment.
	Put(name string, key *sf.PublicKey) error

	// Current returns the current name assignments.
	Current() (ContactInfos, error)
}

// ContactInfo represents the local name for an address.
type ContactInfo struct {
	Name    string
	Address *sf.PublicKey
}

// ContactInfos is a sortable slice of contact information.
type ContactInfos []ContactInfo

// Len implements sort.Interface.
func (c ContactInfos) Len() int { return len(c) }

// Swap implements sort.Interface.
func (c ContactInfos) Swap(i, j int) { c[i], c[j] = c[j], c[i] }

// Less implements sort.Interface.
func (c ContactInfos) Less(i, j int) bool { return c[i].Name < c[j].Name }

// Vault stores public-private key pairs.
type Vault interface {

	// Current returns the latest key pair.
	Current() (*sf.KeyPair, error)

	// Get returns the key pair for the given public key.
	Get(key *sf.PublicKey) (*sf.KeyPair, error)

	// Put adds a new key pair, which becomes the latest, current key pair.
	Put(keyPair *sf.KeyPair) error

	// Each calls the given function with each key pair in the vault.
	//
	// Iteration stops if the function returns an error.
	Each(func(key *sf.KeyPair) error) error
}

// Service stores messages for a shadowfax server.
type Service interface {

	// Push queues a message to a recipient.
	Push(msg *AddressedMessage) error

	// Pop retrieves messages addressed to a recipient and removes them.
	Pop(recipient string) ([]*AddressedMessage, error)
}

// Message is some content with a unique identifier.
type Message struct {
	ID       string
	Contents []byte
}

// AddressedMessage is a Message with a Sender and Recipient public key.
type AddressedMessage struct {
	Message
	Recipient string
	Sender    string
}
