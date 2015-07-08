package client

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"path"

	"golang.org/x/crypto/nacl/box"

	"gopkg.in/errgo.v1"

	sf "github.com/cmars/shadowfax"
	"github.com/cmars/shadowfax/wire"
)

type Client struct {
	keyPair   sf.KeyPair
	serverURL string
	serverKey *sf.PublicKey
	client    *http.Client
}

func PublicKey(serverURL string, client *http.Client) (*sf.PublicKey, error) {
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

func New(keyPair sf.KeyPair, serverURL string, serverKey *sf.PublicKey, client *http.Client) *Client {
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

type PushMessage struct {
	ID        string
	Recipient string
	Contents  []byte
}

func (c *Client) Push(message *PushMessage) error {
	pushWire := []wire.PushMessage{{
		Message: wire.Message{
			ID:       message.ID,
			Contents: message.Contents,
		},
		Recipient: message.Recipient,
	}}

	plaintext, err := json.Marshal(&pushWire)
	if err != nil {
		return errgo.Mask(err)
	}

	nonce, err := sf.NewNonce()
	if err != nil {
		return errgo.Mask(err)
	}
	ciphertext := box.Seal(nil, plaintext, (*[24]byte)(nonce), (*[32]byte)(c.serverKey), (*[32]byte)(c.keyPair.PrivateKey))
	reqMessage := wire.Message{
		ID:       nonce.Encode(),
		Contents: ciphertext,
	}
	reqContents, err := json.Marshal(&reqMessage)
	if err != nil {
		return errgo.Mask(err)
	}

	req, err := http.NewRequest("POST", c.serverURL+"/messages/"+c.keyPair.PublicKey.Encode(), bytes.NewBuffer(reqContents))
	if err != nil {
		return errgo.Mask(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return errgo.Mask(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg := http.StatusText(resp.StatusCode)
		if msg == "" {
			msg = "[Unknown Status]"
		}
		return errgo.Newf("%d %s", resp.StatusCode, msg)
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errgo.Mask(err)
	}
	decBody, ok := box.Open(nil, respBody, (*[24]byte)(nonce), (*[32]byte)(c.serverKey), (*[32]byte)(c.keyPair.PrivateKey))
	if !ok {
		return errgo.New("failed to authenticate response from server")
	}

	var pushReceipts []wire.PushReceipt
	err = json.Unmarshal(decBody, &pushReceipts)
	if err != nil {
		return errgo.Mask(err)
	}

	for _, receipt := range pushReceipts {
		if receipt.OK && receipt.ID == message.ID {
			return nil
		}
	}
	return errgo.New("not acknowledged")
}

type PopMessage struct {
	ID       string
	Sender   string
	Contents []byte
}

func (c *Client) Pop() ([]*PopMessage, error) {
	nonce, err := sf.NewNonce()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	ciphertext := box.Seal(nil, nil, (*[24]byte)(nonce), (*[32]byte)(c.serverKey), (*[32]byte)(c.keyPair.PrivateKey))
	reqMessage := wire.Message{
		ID:       nonce.Encode(),
		Contents: ciphertext,
	}
	reqContents, err := json.Marshal(&reqMessage)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	req, err := http.NewRequest("DELETE", c.serverURL+"/messages/"+c.keyPair.PublicKey.Encode(), bytes.NewBuffer(reqContents))
	if err != nil {
		return nil, errgo.Mask(err)
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg := http.StatusText(resp.StatusCode)
		if msg == "" {
			msg = "[Unknown Status]"
		}
		return nil, errgo.Newf("%d %s", resp.StatusCode, msg)
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	decBody, ok := box.Open(nil, respBody, (*[24]byte)(nonce), (*[32]byte)(c.serverKey), (*[32]byte)(c.keyPair.PrivateKey))
	if !ok {
		return nil, errgo.New("failed to authenticate response from server")
	}

	var wireMessages []wire.PopMessage
	err = json.Unmarshal(decBody, &wireMessages)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	var popMessages []*PopMessage
	for _, msg := range wireMessages {
		popMessages = append(popMessages, &PopMessage{
			ID:       msg.ID,
			Contents: msg.Contents,
			Sender:   msg.Sender,
		})
	}
	return popMessages, nil
}

func (c *Client) PublicKey() *sf.PublicKey {
	return c.keyPair.PublicKey
}
