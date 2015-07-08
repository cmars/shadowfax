package handler_test

import (
	"net/http/httptest"
	"testing"

	"github.com/julienschmidt/httprouter"
	gc "gopkg.in/check.v1"

	sf "github.com/cmars/shadowfax"
	"github.com/cmars/shadowfax/client"
	"github.com/cmars/shadowfax/entities"
	"github.com/cmars/shadowfax/handler"
)

func Test(t *testing.T) { gc.TestingT(t) }

type HttpSuite struct {
	service entities.Service
	keyPair sf.KeyPair
	handler *handler.Handler
	server  *httptest.Server
}

var _ = gc.Suite(&HttpSuite{})

type mockService struct {
	msgs []*entities.AddressedMessage
}

func (s *mockService) Push(msg *entities.AddressedMessage) error {
	s.msgs = append(s.msgs, msg)
	return nil
}

func (s *mockService) Pop(_ string) ([]*entities.AddressedMessage, error) {
	result := s.msgs
	s.msgs = nil
	return result, nil
}

func (s *HttpSuite) SetUpTest(c *gc.C) {
	var err error
	s.service = &mockService{}
	s.keyPair, err = sf.NewKeyPair()
	c.Assert(err, gc.IsNil)
	s.handler = handler.NewHandler(s.keyPair, s.service)

	r := httprouter.New()
	s.handler.Register(r)

	s.server = httptest.NewServer(r)
}

func (s *HttpSuite) TearDownTest(c *gc.C) {
	s.server.Close()
}

func (s *HttpSuite) newClient(c *gc.C) *client.Client {
	kp, err := sf.NewKeyPair()
	c.Assert(err, gc.IsNil)
	return client.New(kp, s.server.URL, s.keyPair.PublicKey, nil)
}

func mustNewNonce() *sf.Nonce {
	n, err := sf.NewNonce()
	if err != nil {
		panic(err)
	}
	return n
}

func (s *HttpSuite) TestPushPop(c *gc.C) {
	alice := s.newClient(c)
	bob := s.newClient(c)

	err := alice.Push(&client.PushMessage{
		ID:        mustNewNonce().Encode(),
		Contents:  []byte("hello world"),
		Recipient: bob.PublicKey().Encode(),
	})
	c.Assert(err, gc.IsNil)

	msgs, err := bob.Pop()
	c.Assert(err, gc.IsNil)
	c.Assert(msgs, gc.HasLen, 1)
}
