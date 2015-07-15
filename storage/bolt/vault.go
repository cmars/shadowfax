package bolt

import (
	"bytes"
	"math/big"

	"github.com/boltdb/bolt"
	"golang.org/x/crypto/nacl/secretbox"
	"gopkg.in/errgo.v1"

	sf "github.com/cmars/shadowfax"
)

type vault struct {
	db        *bolt.DB
	secretKey *sf.SecretKey
}

// NewVault returns a new storage.Vault backed by bolt DB.
func NewVault(db *bolt.DB, secretKey *sf.SecretKey) *vault {
	return &vault{db, secretKey}
}

// Current implements storage.Vault.
func (v *vault) Current() (*sf.KeyPair, error) {
	var keyPair sf.KeyPair
	err := v.db.View(func(tx *bolt.Tx) error {
		logBucket := tx.Bucket([]byte("log"))
		if logBucket == nil {
			return errgo.New("empty vault")
		}

		seqBytes, encBytes := logBucket.Cursor().Last()
		if seqBytes == nil {
			return errgo.New("empty vault")
		}
		seq := new(sf.Nonce)
		copy(seq[:], seqBytes)
		keyPairBytes, ok := secretbox.Open(nil, encBytes, (*[24]byte)(seq), (*[32]byte)(v.secretKey))
		if !ok {
			seq := new(big.Int)
			seq.SetBytes(seqBytes)
			return errgo.Newf("error opening key pair #%s", seq.String())
		}
		keyPair.PublicKey = new(sf.PublicKey)
		copy(keyPair.PublicKey[:], keyPairBytes[:32])
		keyPair.PrivateKey = new(sf.PrivateKey)
		copy(keyPair.PrivateKey[:], keyPairBytes[32:])
		// TODO: mprotect private key
		// TODO: zeroize keyPairBytes

		return nil
	})
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return &keyPair, nil
}

// Get implements storage.Vault.
func (v *vault) Get(key *sf.PublicKey) (*sf.KeyPair, error) {
	var keyPair sf.KeyPair
	err := v.db.View(func(tx *bolt.Tx) error {
		keysBucket := tx.Bucket([]byte("keys"))
		if keysBucket == nil {
			return errgo.New("empty vault")
		}
		logBucket := tx.Bucket([]byte("log"))
		if logBucket == nil {
			return errgo.New("empty vault")
		}

		seqBytes := keysBucket.Get(key[:])
		if seqBytes == nil {
			return errgo.Newf("key pair not found for %q", key.Encode())
		}
		seqInt := new(big.Int)
		seqInt.SetBytes(seqBytes)
		encBytes := logBucket.Get(seqBytes)
		if encBytes == nil {
			return errgo.Newf("missing expected key #%s", seqInt.String())
		}
		seq := new(sf.Nonce)
		copy(seq[:], seqBytes)

		keyPairBytes, ok := secretbox.Open(nil, encBytes, (*[24]byte)(seq), (*[32]byte)(v.secretKey))
		if !ok {
			return errgo.Newf("error opening key pair #%s", seqInt.String())
		}
		keyPair.PublicKey = new(sf.PublicKey)
		copy(keyPair.PublicKey[:], keyPairBytes[:32])
		keyPair.PrivateKey = new(sf.PrivateKey)
		copy(keyPair.PrivateKey[:], keyPairBytes[32:])
		// TODO: mprotect private key
		// TODO: zeroize keyPairBytes

		return nil
	})
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return &keyPair, nil
}

// Put implements storage.Vault.
func (v *vault) Put(keyPair *sf.KeyPair) error {
	return v.db.Update(func(tx *bolt.Tx) error {
		keysBucket, err := tx.CreateBucketIfNotExists([]byte("keys"))
		if err != nil {
			return errgo.Mask(err)
		}
		logBucket, err := tx.CreateBucketIfNotExists([]byte("log"))
		if err != nil {
			return errgo.Mask(err)
		}

		seqBytes, _ := logBucket.Cursor().Last()
		seqInt := new(big.Int)
		seqInt.SetBytes(seqBytes)
		seqInt.Add(seqInt, bigOne)
		seq := new(sf.Nonce)
		copy(seq[:], seqInt.Bytes())

		var kpBuf bytes.Buffer
		_, err = kpBuf.Write(keyPair.PublicKey[:])
		if err != nil {
			return errgo.Mask(err)
		}
		_, err = kpBuf.Write(keyPair.PrivateKey[:])
		if err != nil {
			return errgo.Mask(err)
		}
		encBytes := secretbox.Seal(nil, kpBuf.Bytes(), (*[24]byte)(seq), (*[32]byte)(v.secretKey))
		// TODO: zeroize kpBuf
		err = keysBucket.Put(keyPair.PublicKey[:], seq[:])
		if err != nil {
			return errgo.Mask(err)
		}
		err = logBucket.Put(seq[:], encBytes)
		if err != nil {
			return errgo.Mask(err)
		}

		return nil
	})
}
