package bolt_test

import (
	"path/filepath"

	"github.com/boltdb/bolt"
	gc "gopkg.in/check.v1"

	sf "github.com/cmars/shadowfax"
	sfbolt "github.com/cmars/shadowfax/storage/bolt"
	sftesting "github.com/cmars/shadowfax/testing"
)

type contactsSuite struct {
	db *bolt.DB
}

var _ = gc.Suite(&contactsSuite{})

func (s *contactsSuite) SetUpTest(c *gc.C) {
	dir := c.MkDir()
	var err error
	s.db, err = bolt.Open(filepath.Join(dir, "testdb"), 0600, nil)
	c.Assert(err, gc.IsNil)
}

func (s *contactsSuite) TestContacts(c *gc.C) {
	bob := sftesting.MustNewKeyPair()
	carol := sftesting.MustNewKeyPair()

	aliceContacts := sfbolt.NewContacts(s.db)
	aliceContacts.Put("bob", bob.PublicKey)
	aliceContacts.Put("carol", carol.PublicKey)

	var err error
	var key *sf.PublicKey

	key, err = aliceContacts.Key("bob")
	c.Assert(err, gc.IsNil)
	c.Assert(key, gc.DeepEquals, bob.PublicKey)
	key, err = aliceContacts.Key("carol")
	c.Assert(err, gc.IsNil)
	c.Assert(key, gc.DeepEquals, carol.PublicKey)
	for _, noName := range []string{"dave", "trent"} {
		_, err = aliceContacts.Key(noName)
		c.Assert(err, gc.ErrorMatches, `key not found for "`+noName+`"`)
	}

	bob2 := sftesting.MustNewKeyPair()
	aliceContacts.Put("bob", bob2.PublicKey)
	key, err = aliceContacts.Key("bob")
	c.Assert(err, gc.IsNil)
	c.Assert(key, gc.DeepEquals, bob2.PublicKey)
}
