/*
  Copyright 2015 Casey Marshall.

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

package http_test

import (
	"testing"

	gc "gopkg.in/check.v1"

	"github.com/cmars/shadowfax/storage"
	sftesting "github.com/cmars/shadowfax/testing"
)

func Test(t *testing.T) { gc.TestingT(t) }

type mockHandlerSuite struct {
	*sftesting.HTTPHandlerSuite
}

var _ = gc.Suite(&mockHandlerSuite{&sftesting.HTTPHandlerSuite{}})

type mockService struct {
	msgs   []*storage.AddressedMessage
	onPush func(msg *storage.AddressedMessage)
	onPop  func(msgs []*storage.AddressedMessage)
}

func (s *mockService) Push(msg *storage.AddressedMessage) error {
	if s.onPush != nil {
		s.onPush(msg)
	}
	s.msgs = append(s.msgs, msg)
	return nil
}

func (s *mockService) Pop(_ string) ([]*storage.AddressedMessage, error) {
	result := s.msgs
	s.msgs = nil
	if s.onPop != nil {
		s.onPop(result)
	}
	return result, nil
}

func (s *mockHandlerSuite) SetUpTest(c *gc.C) {
	s.HTTPHandlerSuite.SetStorage(&mockService{})
	s.HTTPHandlerSuite.SetUpTest(c)
}

func (s *mockHandlerSuite) TearDownTest(c *gc.C) {
	s.HTTPHandlerSuite.TearDownTest(c)
}

func (s *mockHandlerSuite) TestPushPop(c *gc.C) {
	alice := s.NewClient(c)
	bob := s.NewClient(c)

	st := s.Storage().(*mockService)

	var msgNonce string
	st.onPush = func(msg *storage.AddressedMessage) {
		c.Assert(msg.Sender, gc.Equals, alice.PublicKey().Encode())
		c.Assert(msg.Recipient, gc.Equals, bob.PublicKey().Encode())
		c.Assert(len(msg.Contents) > 0, gc.Equals, true)
		c.Assert(msg.Contents, gc.Not(gc.DeepEquals), []byte("hello world"))
		msgNonce = msg.ID
	}
	st.onPop = func(msgs []*storage.AddressedMessage) {
		c.Assert(msgs, gc.HasLen, 1)
		c.Assert(msgs[0].ID, gc.Equals, msgNonce)
		st.onPush(msgs[0])
	}

	err := alice.Push(bob.PublicKey().Encode(), []byte("hello world"))
	c.Assert(err, gc.IsNil)

	msgs, err := bob.Pop()
	c.Assert(err, gc.IsNil)
	c.Assert(msgs, gc.HasLen, 1)
	c.Assert(msgs[0].Contents, gc.DeepEquals, []byte("hello world"))
}
