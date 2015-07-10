package http_test

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/julienschmidt/httprouter"
	gc "gopkg.in/check.v1"

	sf "github.com/cmars/shadowfax"
	"github.com/cmars/shadowfax/entities"
	sfhttp "github.com/cmars/shadowfax/http"
)

func Test(t *testing.T) { gc.TestingT(t) }

type HttpSuite struct {
	service   *mockService
	keyPair   sf.KeyPair
	handler   *sfhttp.Handler
	server    *httptest.Server
	tlsServer *httptest.Server
}

var _ = gc.Suite(&HttpSuite{})

type mockService struct {
	msgs   []*entities.AddressedMessage
	onPush func(msg *entities.AddressedMessage)
	onPop  func(msgs []*entities.AddressedMessage)
}

func (s *mockService) Push(msg *entities.AddressedMessage) error {
	if s.onPush != nil {
		s.onPush(msg)
	}
	s.msgs = append(s.msgs, msg)
	return nil
}

func (s *mockService) Pop(_ string) ([]*entities.AddressedMessage, error) {
	result := s.msgs
	s.msgs = nil
	if s.onPop != nil {
		s.onPop(result)
	}
	return result, nil
}

func (s *HttpSuite) SetUpTest(c *gc.C) {
	var err error
	s.service = &mockService{}
	s.keyPair, err = sf.NewKeyPair()
	c.Assert(err, gc.IsNil)
	s.handler = sfhttp.NewHandler(s.keyPair, s.service)

	r := httprouter.New()
	s.handler.Register(r)

	s.server = httptest.NewServer(r)
	s.tlsServer = httptest.NewTLSServer(r)
}

func (s *HttpSuite) TearDownTest(c *gc.C) {
	s.server.Close()
}

func (s *HttpSuite) newClient(c *gc.C) *sfhttp.Client {
	kp, err := sf.NewKeyPair()
	c.Assert(err, gc.IsNil)
	return sfhttp.NewClient(kp, s.server.URL, s.keyPair.PublicKey, nil)
}

func mustNewNonce() *sf.Nonce {
	n, err := sf.NewNonce()
	if err != nil {
		panic(err)
	}
	return n
}

func (s *HttpSuite) TestPublicKey(c *gc.C) {
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

func (s *HttpSuite) TestPushPop(c *gc.C) {
	alice := s.newClient(c)
	bob := s.newClient(c)

	var msgNonce string
	s.service.onPush = func(msg *entities.AddressedMessage) {
		c.Assert(msg.Sender, gc.Equals, alice.PublicKey().Encode())
		c.Assert(msg.Recipient, gc.Equals, bob.PublicKey().Encode())
		c.Assert(len(msg.Contents) > 0, gc.Equals, true)
		c.Assert(msg.Contents, gc.Not(gc.DeepEquals), []byte("hello world"))
		msgNonce = msg.ID
	}
	s.service.onPop = func(msgs []*entities.AddressedMessage) {
		c.Assert(msgs, gc.HasLen, 1)
		c.Assert(msgs[0].ID, gc.Equals, msgNonce)
		s.service.onPush(msgs[0])
	}

	err := alice.Push(bob.PublicKey().Encode(), []byte("hello world"))
	c.Assert(err, gc.IsNil)

	msgs, err := bob.Pop()
	c.Assert(err, gc.IsNil)
	c.Assert(msgs, gc.HasLen, 1)
	c.Assert(msgs[0].Contents, gc.DeepEquals, []byte("hello world"))
}
