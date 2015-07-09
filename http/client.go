package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"

	"golang.org/x/crypto/nacl/box"

	"gopkg.in/errgo.v1"

	sf "github.com/cmars/shadowfax"
	"github.com/cmars/shadowfax/wire"
)

// Client pushes and pops messages in the shadowfax messaging system.
type Client struct {
	keyPair   sf.KeyPair
	serverURL string
	serverKey *sf.PublicKey
	client    *http.Client
}

// PublicKey requests a shadowfax server's public key. An error is returned
// if the server URL is not https.
func PublicKey(serverURL string, client *http.Client) (*sf.PublicKey, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	if u.Scheme != "https" {
		return nil, errgo.Newf("public key must be requested with https")
	}
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequest("GET", path.Join(serverURL, "publickey"), nil)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	var publicKeyResp wire.PublicKeyResponse
	err = dec.Decode(&publicKeyResp)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	publicKey, err := sf.DecodePublicKey(publicKeyResp.PublicKey)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return publicKey, nil
}

// NewClient returns a new shadowfax client.
func NewClient(keyPair sf.KeyPair, serverURL string, serverKey *sf.PublicKey, client *http.Client) *Client {
	if client == nil {
		client = http.DefaultClient
	}
	return &Client{
		keyPair:   keyPair,
		serverURL: serverURL,
		serverKey: serverKey,
		client:    client,
	}
}

// Request encrypts a request to the router and decrypts the response.
//
// If the client and server have securely exchanged keys out of band,
// confidentiality does not depend on TLS.
func (c *Client) Request(method string, path string, contents []byte) ([]byte, error) {
	nonce, err := sf.NewNonce()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	encReq := box.Seal(nil, contents, (*[24]byte)(nonce), (*[32]byte)(c.serverKey), (*[32]byte)(c.keyPair.PrivateKey))
	reqMessage := wire.Message{
		ID:       nonce.Encode(),
		Contents: encReq,
	}
	reqContents, err := json.Marshal(&reqMessage)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	req, err := http.NewRequest(method, c.serverURL+path, bytes.NewBuffer(reqContents))
	if err != nil {
		return nil, errgo.Mask(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	defer resp.Body.Close()
	respContents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errgo.Mask(newHTTPClientError(resp.StatusCode, string(respContents)))
	}
	decResp, ok := box.Open(nil, respContents, (*[24]byte)(nonce), (*[32]byte)(c.serverKey), (*[32]byte)(c.keyPair.PrivateKey))
	if !ok {
		return nil, errgo.New("failed to authenticate response from server")
	}
	return decResp, nil
}

type httpClientError struct {
	code    int
	message string
}

func newHTTPClientError(code int, message string) *httpClientError {
	return &httpClientError{code: code, message: message}
}

// Error implements the error interface.
func (err *httpClientError) Error() string {
	return fmt.Sprintf("server response: %d %s %q", err.code, http.StatusText(err.code), err.message)
}

// Push pushes a message to a recipient.
func (c *Client) Push(recipient string, contents []byte) error {
	nonce, err := sf.NewNonce()
	if err != nil {
		return errgo.Mask(err)
	}
	rcptKey, err := sf.DecodePublicKey(recipient)
	if err != nil {
		return errgo.Mask(err)
	}
	encMsg := box.Seal(nil, contents, (*[24]byte)(nonce), (*[32]byte)(rcptKey), (*[32]byte)(c.keyPair.PrivateKey))
	pushWire := []wire.PushMessage{{
		Message: wire.Message{
			ID:       nonce.Encode(),
			Contents: encMsg,
		},
		Recipient: recipient,
	}}
	reqContents, err := json.Marshal(&pushWire)
	if err != nil {
		return errgo.Mask(err)
	}

	respContents, err := c.Request("POST", "/outbox/"+c.keyPair.PublicKey.Encode(), reqContents)
	if err != nil {
		return errgo.Mask(err)
	}
	var pushReceipts []wire.PushReceipt
	err = json.Unmarshal(respContents, &pushReceipts)
	if err != nil {
		return errgo.Mask(err)
	}
	for _, receipt := range pushReceipts {
		if receipt.OK && receipt.ID == nonce.Encode() {
			return nil
		}
	}
	return errgo.New("not acknowledged")
}

// PopMessage contains a message received.
type PopMessage struct {
	ID       string
	Sender   string
	Contents []byte
}

type errorSlice []error

// Error implements the error interface.
func (errs errorSlice) Error() string {
	var errmsgs []string
	for _, err := range errs {
		errmsgs = append(errmsgs, errgo.Details(err))
	}
	return strings.Join(errmsgs, "\n")
}

// Pop retrieves messages addressed to the client.
func (c *Client) Pop() ([]*PopMessage, error) {
	respContents, err := c.Request("DELETE", "/inbox/"+c.keyPair.PublicKey.Encode(), nil)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	var wireMessages []wire.PopMessage
	err = json.Unmarshal(respContents, &wireMessages)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	var popMessages []*PopMessage
	var errors errorSlice
	for _, msg := range wireMessages {
		nonce, err := sf.DecodeNonce(msg.ID)
		if err != nil {
			errors = append(errors, errgo.Notef(err, "ID=%q Sender=%q", msg.ID, msg.Sender))
			continue
		}
		senderKey, err := sf.DecodePublicKey(msg.Sender)
		if err != nil {
			errors = append(errors, errgo.Notef(err, "ID=%q Sender=%q", msg.ID, msg.Sender))
			continue
		}
		contents, ok := box.Open(nil, msg.Contents, (*[24]byte)(nonce), (*[32]byte)(senderKey), (*[32]byte)(c.keyPair.PrivateKey))
		if !ok {
			errors = append(errors, errgo.Newf("invalid message contents: ID=%q Sender=%q", msg.ID, msg.Sender))
			continue
		}
		popMessages = append(popMessages, &PopMessage{
			ID:       msg.ID,
			Contents: contents,
			Sender:   msg.Sender,
		})
	}
	return popMessages, errors
}

// PublicKey returns the public key identity of the client.
func (c *Client) PublicKey() *sf.PublicKey {
	return c.keyPair.PublicKey
}
