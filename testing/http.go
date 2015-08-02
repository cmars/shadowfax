/*
  Copyright 2015 Casey Marshall.

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

package testing

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"

	"github.com/julienschmidt/httprouter"
	gc "gopkg.in/check.v1"

	sf "github.com/cmars/shadowfax"
	sfhttp "github.com/cmars/shadowfax/http"
	"github.com/cmars/shadowfax/storage"
)

type HTTPHandlerSuite struct {
	service   storage.Service
	keyPair   *sf.KeyPair
	handler   *sfhttp.Handler
	server    *httptest.Server
	tlsServer *httptest.Server
}

func (s *HTTPHandlerSuite) SetStorage(st storage.Service) {
	s.service = st
}

func (s *HTTPHandlerSuite) Storage() storage.Service {
	return s.service
}

func (s *HTTPHandlerSuite) PublicKey() *sf.PublicKey {
	return s.keyPair.PublicKey
}

func (s *HTTPHandlerSuite) SetUpTest(c *gc.C) {
	c.Assert(s.service, gc.NotNil)

	r := httprouter.New()
	s.keyPair = MustNewKeyPair()
	s.handler = sfhttp.NewHandler(s.keyPair, s.service)
	s.handler.Register(r)
	s.server = httptest.NewServer(r)
	s.tlsServer = httptest.NewTLSServer(r)
}

func (s *HTTPHandlerSuite) TearDownTest(c *gc.C) {
	s.server.Close()
	s.tlsServer.Close()
}

func (s *HTTPHandlerSuite) NewClient(c *gc.C) *sfhttp.Client {
	kp := MustNewKeyPair()
	return sfhttp.NewClient(kp, s.server.URL, s.keyPair.PublicKey, nil)
}

func MustNewNonce() *sf.Nonce {
	n, err := sf.NewNonce()
	if err != nil {
		panic(err)
	}
	return n
}

func MustNewKeyPair() *sf.KeyPair {
	kp, err := sf.NewKeyPair()
	if err != nil {
		panic(err)
	}
	return &kp
}

func (s *HTTPHandlerSuite) TestPublicKey(c *gc.C) {
	pk, err := sfhttp.PublicKey(s.server.URL+"/publickey", nil)
	c.Assert(err, gc.ErrorMatches, ".*public key must be requested with https.*")
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	pk, err = sfhttp.PublicKey(s.tlsServer.URL, httpClient)
	c.Assert(err, gc.IsNil)
	c.Assert(pk.Encode(), gc.Equals, s.keyPair.PublicKey.Encode())
}

func (s *HTTPHandlerSuite) TestPushPop(c *gc.C) {
	alice := s.NewClient(c)
	bob := s.NewClient(c)

	err := alice.Push(bob.PublicKey().Encode(), []byte("hello world"))
	c.Assert(err, gc.IsNil)

	msgs, err := bob.Pop()
	c.Assert(err, gc.IsNil)
	c.Assert(msgs, gc.HasLen, 1)
	c.Assert(msgs[0].Contents, gc.DeepEquals, []byte("hello world"))

	msgs, err = bob.Pop()
	c.Assert(err, gc.IsNil)
	c.Assert(msgs, gc.HasLen, 0)
}
