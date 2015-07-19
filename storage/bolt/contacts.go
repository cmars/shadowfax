package bolt

import (
	"math/big"

	"github.com/boltdb/bolt"
	"gopkg.in/errgo.v1"

	sf "github.com/cmars/shadowfax"
	"github.com/cmars/shadowfax/storage"
)

var (
	bigOne = big.NewInt(1)
)

type contacts struct {
	db *bolt.DB
}

// NewContacts returns a new storage.Contacts backed by bolt DB.
func NewContacts(db *bolt.DB) *contacts {
	return &contacts{db}
}

// Key implements storage.Contacts.
func (c *contacts) Key(name string) (*sf.PublicKey, error) {
	var pk sf.PublicKey
	err := c.db.View(func(tx *bolt.Tx) error {
		contactsBucket := tx.Bucket([]byte("contacts"))
		if contactsBucket == nil {
			return errgo.Newf("key not found for %q", name)
		}
		keysBucket := contactsBucket.Bucket([]byte(name))
		if keysBucket == nil {
			return errgo.Newf("key not found for %q", name)
		}
		seqBytes, pkBytes := keysBucket.Cursor().Last()
		if seqBytes == nil {
			return errgo.Newf("key not found for %q", name)
		}
		copy(pk[:], pkBytes)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &pk, nil
}

// Name implements storage.Contacts.
func (c *contacts) Name(key *sf.PublicKey) (string, error) {
	var name []byte
	var fail string
	err := c.db.View(func(tx *bolt.Tx) error {
		contactsBucket := tx.Bucket([]byte("contacts"))
		if contactsBucket == nil {
			return errgo.New("key not found")
		}
		name = contactsBucket.Get(key[:])
		return nil
	})
	if err != nil {
		return fail, err
	}
	if len(name) == 0 {
		return "", errgo.Newf("no contact found for %q", key.Encode())
	}
	return string(name), nil
}

// Put implements storage.Contacts.
func (c *contacts) Put(name string, key *sf.PublicKey) error {
	if len(name) == 0 {
		return errgo.New("empty key name")
	}
	return c.db.Update(func(tx *bolt.Tx) error {
		contactsBucket, err := tx.CreateBucketIfNotExists([]byte("contacts"))
		if err != nil {
			return errgo.Mask(err)
		}
		err = contactsBucket.Put(key[:], []byte(name))
		if err != nil {
			return errgo.Mask(err)
		}
		keysBucket, err := contactsBucket.CreateBucketIfNotExists([]byte(name))
		if err != nil {
			return errgo.Mask(err)
		}

		lastSeqBytes, _ := keysBucket.Cursor().Last()
		var seq big.Int
		seq.SetBytes(lastSeqBytes)
		seq.Add(&seq, bigOne)
		err = keysBucket.Put(seq.Bytes(), key[:])
		if err != nil {
			return errgo.Mask(err)
		}
		return nil
	})
}

func (c *contacts) Current() (storage.ContactInfos, error) {
	var result storage.ContactInfos
	err := c.db.View(func(tx *bolt.Tx) error {
		contactsBucket := tx.Bucket([]byte("contacts"))
		if contactsBucket == nil {
			// empty contacts
			return nil
		}
		cur := contactsBucket.Cursor()
		for name, _ := cur.First(); name != nil; name, _ = cur.Next() {
			keysBucket := contactsBucket.Bucket([]byte(name))
			if keysBucket == nil {
				// TODO: warning, name has no keys!
				continue
			}
			seqBytes, pkBytes := keysBucket.Cursor().Last()
			if seqBytes == nil {
				// TODO: warning, empty bucket!
				continue
			}
			pk := new(sf.PublicKey)
			copy(pk[:], pkBytes)
			result = append(result, storage.ContactInfo{
				Name:    string(name),
				Address: pk,
			})
		}
		return nil
	})
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return result, nil
}
