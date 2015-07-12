package storage

import (
	sf "github.com/cmars/shadowfax"
)

type Contacts interface {
	Key(name string) (*sf.PublicKey, error)
	Name(key *sf.PublicKey) (string, error)
	Put(name string, key *sf.PublicKey) error
}

type Vault interface {
	Current() (*sf.KeyPair, error)
	Get(key *sf.PublicKey) (*sf.KeyPair, error)
	Put(keyPair *sf.KeyPair) error
}

type Service interface {
	Push(msg *AddressedMessage) error
	Pop(recipient string) ([]*AddressedMessage, error)
}

type Message struct {
	ID       string
	Contents []byte
}

type AddressedMessage struct {
	Message
	Recipient string
	Sender    string
}
