package bolt

import (
	"github.com/boltdb/bolt"
	"gopkg.in/basen.v1"
	"gopkg.in/errgo.v1"

	sf "github.com/cmars/shadowfax"
	"github.com/cmars/shadowfax/storage"
)

type service struct {
	db *bolt.DB
}

func NewService(db *bolt.DB) *service {
	return &service{db}
}

func (s *service) Push(msg *storage.AddressedMessage) error {
	rcptKey, err := sf.DecodePublicKey(msg.Recipient)
	if err != nil {
		return errgo.Notef(err, "invalid recipient %q", msg.Recipient)
	}
	senderKey, err := sf.DecodePublicKey(msg.Sender)
	if err != nil {
		return errgo.Notef(err, "invalid sender %q", msg.Sender)
	}
	nonce, err := sf.DecodeNonce(msg.ID)
	if err != nil {
		return errgo.Notef(err, "invalid nonce %q", msg.ID)
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		rcptBucket, err := tx.CreateBucketIfNotExists(rcptKey[:])
		if err != nil {
			return errgo.Mask(err)
		}
		senderBucket, err := rcptBucket.CreateBucketIfNotExists(senderKey[:])
		if err != nil {
			return errgo.Mask(err)
		}
		err = senderBucket.Put(nonce[:], msg.Contents)
		if err != nil {
			return errgo.Mask(err)
		}
		return nil
	})
}

func (s *service) Pop(recipient string) (_ []*storage.AddressedMessage, popErr error) {
	rcptKey, err := sf.DecodePublicKey(recipient)
	if err != nil {
		return nil, errgo.Notef(err, "invalid recipient %q", recipient)
	}

	tx, err := s.db.Begin(true)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	defer func() {
		if popErr == nil {
			popErr = errgo.Mask(tx.Commit())
		} else {
			tx.Rollback()
		}
	}()

	var result []*storage.AddressedMessage
	rcptBucket, err := tx.CreateBucketIfNotExists(rcptKey[:])
	if err != nil {
		return nil, errgo.Mask(err)
	}
	senderCursor := rcptBucket.Cursor()
	for sender, v := senderCursor.First(); sender != nil; sender, v = senderCursor.Next() {
		if v != nil {
			continue
		}
		senderBucket := rcptBucket.Bucket(sender)
		if senderBucket == nil {
			err = senderCursor.Delete()
			if err != nil {
				return nil, errgo.Mask(err)
			}
			continue
		}
		senderStr := basen.Base58.EncodeToString(sender)
		msgCursor := senderBucket.Cursor()
		for id, msg := msgCursor.First(); id != nil; id, msg = msgCursor.Next() {
			idStr := basen.Base58.EncodeToString(id)
			msgContents := make([]byte, len(msg))
			copy(msgContents, msg)
			result = append(result, &storage.AddressedMessage{
				Recipient: recipient,
				Sender:    senderStr,
				Message: storage.Message{
					ID:       idStr,
					Contents: msgContents,
				},
			})
			msgCursor.Delete()
			if err != nil {
				return nil, errgo.Mask(err)
			}
		}
	}
	return result, nil
}
