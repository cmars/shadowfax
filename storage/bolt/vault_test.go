/*
  Copyright 2015 Casey Marshall.

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

package bolt_test

import (
	"path/filepath"

	"github.com/boltdb/bolt"
	gc "gopkg.in/check.v1"

	sf "github.com/cmars/shadowfax"
	sfbolt "github.com/cmars/shadowfax/storage/bolt"
)

type vaultSuite struct {
	db *bolt.DB
}

var _ = gc.Suite(&vaultSuite{})

func (s *vaultSuite) SetUpTest(c *gc.C) {
	dir := c.MkDir()
	var err error
	s.db, err = bolt.Open(filepath.Join(dir, "testdb"), 0600, nil)
	c.Assert(err, gc.IsNil)
}

func (s *vaultSuite) TestVault(c *gc.C) {
	secKey, err := sf.NewSecretKey()
	v := sfbolt.NewVault(s.db, secKey)

	_, err = v.Current()
	c.Assert(err, gc.ErrorMatches, "empty vault")

	var kp *sf.KeyPair

	kp1, err := sf.NewKeyPair()
	c.Assert(err, gc.IsNil)
	err = v.Put(&kp1)
	c.Assert(err, gc.IsNil)
	kp, err = v.Get(kp1.PublicKey)
	c.Assert(err, gc.IsNil)
	c.Assert(kp, gc.DeepEquals, &kp1)
	kp, err = v.Current()
	c.Assert(err, gc.IsNil)
	c.Assert(kp, gc.DeepEquals, &kp1)

	kp2, err := sf.NewKeyPair()
	c.Assert(err, gc.IsNil)
	err = v.Put(&kp2)
	c.Assert(err, gc.IsNil)
	kp, err = v.Get(kp2.PublicKey)
	c.Assert(err, gc.IsNil)
	c.Assert(kp, gc.DeepEquals, &kp2)
	kp, err = v.Current()
	c.Assert(err, gc.IsNil)
	c.Assert(kp, gc.DeepEquals, &kp2)

	// Can still look up prior key pair by public key.
	kp, err = v.Get(kp1.PublicKey)
	c.Assert(err, gc.IsNil)
	c.Assert(kp, gc.DeepEquals, &kp1)
}
