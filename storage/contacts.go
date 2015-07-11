package storage

import (
	sf "github.com/cmars/shadowfax"
)

type Contacts interface {
	Key(name string) (*sf.PublicKey, error)
	Name(key *sf.PublicKey) (string, error)
	Put(name, context string) error
}

type Vault interface {
	GetLatest(tag string) (*sf.KeyPair, error)
	Get(key *sf.PublicKey) (*sf.KeyPair, error)
	Put(tag string, keyPair *sf.KeyPair) error
}
