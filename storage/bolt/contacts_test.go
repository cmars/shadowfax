/*
  Copyright 2015 Casey Marshall.

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

package bolt_test

import (
	"path/filepath"
	"sort"

	"github.com/boltdb/bolt"
	gc "gopkg.in/check.v1"

	sf "github.com/cmars/shadowfax"
	"github.com/cmars/shadowfax/storage"
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

	cinfos, err := aliceContacts.Current()
	c.Assert(err, gc.IsNil)
	sort.Sort(cinfos)
	c.Assert(cinfos, gc.DeepEquals, storage.ContactInfos{{
		Name:    "bob",
		Address: bob2.PublicKey,
	}, {
		Name:    "carol",
		Address: carol.PublicKey,
	}})
}

func (s *contactsSuite) TestSameName(c *gc.C) {
	alice := sftesting.MustNewKeyPair()
	bob := sftesting.MustNewKeyPair()

	testContacts := sfbolt.NewContacts(s.db)
	testContacts.Put("test", alice.PublicKey)
	testContacts.Put("test", bob.PublicKey)
	name, err := testContacts.Name(alice.PublicKey)
	c.Assert(err, gc.IsNil)
	c.Assert(name, gc.Equals, "test")
	name, err = testContacts.Name(bob.PublicKey)
	c.Assert(err, gc.IsNil)
	c.Assert(name, gc.Equals, "test")
	key, err := testContacts.Key("test")
	c.Assert(err, gc.IsNil)
	c.Assert(key, gc.DeepEquals, bob.PublicKey)
}

func (s *contactsSuite) TestSameKey(c *gc.C) {
	alice := sftesting.MustNewKeyPair()

	testContacts := sfbolt.NewContacts(s.db)
	for _, name := range []string{"go", "ask", "alice", "when", "shes", "ten", "feet", "tall"} {
		testContacts.Put(name, alice.PublicKey)
	}
	name, err := testContacts.Name(alice.PublicKey)
	c.Assert(err, gc.IsNil)
	c.Assert(name, gc.Equals, "tall", gc.Commentf("expect last name set"))
	key, err := testContacts.Key("alice")
	c.Assert(err, gc.IsNil)
	c.Assert(key, gc.DeepEquals, alice.PublicKey)
	key, err = testContacts.Key("when")
	c.Assert(err, gc.IsNil)
	c.Assert(key, gc.DeepEquals, alice.PublicKey)
}
