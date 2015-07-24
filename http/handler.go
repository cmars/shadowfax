package http

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"

	"github.com/julienschmidt/httprouter"
	"golang.org/x/crypto/nacl/box"
	"gopkg.in/errgo.v1"

	sf "github.com/cmars/shadowfax"
	"github.com/cmars/shadowfax/storage"
	"github.com/cmars/shadowfax/wire"
)

// Handler handles HTTP requests as a shadowfax server.
type Handler struct {
	keyPair *sf.KeyPair
	service storage.Service
}

// NewHandler returns a new Handler with public key pair and service backend.
func NewHandler(keyPair *sf.KeyPair, service storage.Service) *Handler {
	return &Handler{
		keyPair: keyPair,
		service: service,
	}
}

// Register sets up endpoint routing for a shadowfax server.
func (h *Handler) Register(r *httprouter.Router) {
	r.GET("/publickey", h.publicKey)
	r.DELETE("/inbox/:recipient", h.pop)
	r.POST("/outbox/:sender", h.push)
}

func logError(err error) {
	log.Println(errgo.Details(err))
}

func httpError(w http.ResponseWriter, wireError wire.Error, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(wireError.Code)
	enc := json.NewEncoder(w)
	encErr := enc.Encode(&wireError)
	if encErr != nil {
		log.Println("failed to encode error response: %v", encErr)
	}
	logError(err)
}

func (h *Handler) publicKey(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	w.Header().Set("Content-Type", "application/json")
	resp := wire.PublicKeyResponse{
		PublicKey: h.keyPair.PublicKey.Encode(),
	}
	buf, err := json.Marshal(&resp)
	if err != nil {
		httpError(w, wire.Error{Code: http.StatusInternalServerError}, errgo.Mask(err))
		return
	}
	w.Write(buf)
}

type authRequest struct {
	*Handler
	ClientKey *sf.PublicKey
	Nonce     *sf.Nonce
	Contents  []byte
}

func (h *Handler) auth(r *http.Request, client string) (*authRequest, error) {
	var msg wire.Message
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&msg)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	clientKey, err := sf.DecodePublicKey(client)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	nonce, err := sf.DecodeNonce(msg.ID)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	out, ok := box.Open(nil, msg.Contents, (*[24]byte)(nonce), (*[32]byte)(clientKey), (*[32]byte)(h.keyPair.PrivateKey))
	if !ok {
		return nil, errgo.New("authentication failed")
	}

	return &authRequest{
		Handler:   h,
		ClientKey: clientKey,
		Nonce:     nonce,
		Contents:  out,
	}, nil
}

func (a *authRequest) resp(w http.ResponseWriter, data interface{}) {
	var msg bytes.Buffer

	enc := json.NewEncoder(&msg)
	err := enc.Encode(data)
	if err != nil {
		httpError(w, wire.Error{Code: http.StatusInternalServerError}, errgo.Mask(err))
		return
	}

	out := box.Seal(nil, msg.Bytes(), (*[24]byte)(a.Nonce), (*[32]byte)(a.ClientKey), (*[32]byte)(a.keyPair.PrivateKey))
	_, err = w.Write(out)
	if err != nil {
		logError(errgo.Mask(err))
	}
}

func (h *Handler) pop(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	w.Header().Set("Content-Type", "application/json")

	auth, err := h.auth(r, p.ByName("recipient"))
	if err != nil {
		httpError(w, wire.Error{Code: http.StatusBadRequest}, errgo.Mask(err))
		return
	}

	messages, err := h.service.Pop(auth.ClientKey.Encode())
	if err != nil {
		httpError(w, wire.Error{Code: http.StatusInternalServerError}, errgo.Mask(err))
		return
	}

	var wireMessages []wire.PopMessage
	for _, entityMessage := range messages {
		wireMessages = append(wireMessages, wire.PopMessage{
			Message: wire.Message{
				ID:       entityMessage.ID,
				Contents: entityMessage.Contents,
			},
			Sender: entityMessage.Sender,
		})
	}

	auth.resp(w, wireMessages)
}

func (h *Handler) push(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	w.Header().Set("Content-Type", "application/json")

	auth, err := h.auth(r, p.ByName("sender"))
	if err != nil {
		httpError(w, wire.Error{Code: http.StatusBadRequest}, errgo.Mask(err))
		return
	}

	var wireMessages []wire.PushMessage
	err = json.Unmarshal(auth.Contents, &wireMessages)
	if err != nil {
		httpError(w, wire.Error{Code: http.StatusBadRequest}, errgo.Mask(err))
		return
	}

	var entityMessages []*storage.AddressedMessage
	for _, wireMessage := range wireMessages {
		if wireMessage.Recipient != "" {
			entityMessages = append(entityMessages, &storage.AddressedMessage{
				Recipient: wireMessage.Recipient,
				Sender:    auth.ClientKey.Encode(),
				Message: storage.Message{
					ID:       wireMessage.ID,
					Contents: wireMessage.Contents,
				},
			})
		}
	}

	receipts := make(map[string]wire.PushReceipt)
	for _, entityMessage := range entityMessages {
		if receipt, ok := receipts[entityMessage.ID]; ok && receipt.OK {
			continue
		}

		err := h.service.Push(entityMessage)
		if err != nil {
			receipts[entityMessage.ID] = wire.PushReceipt{
				ID: entityMessage.ID,
				OK: false,
			}
		} else {
			receipts[entityMessage.ID] = wire.PushReceipt{
				ID: entityMessage.ID,
				OK: true,
			}
		}
	}

	var pushReceipts []wire.PushReceipt
	for _, receipt := range receipts {
		pushReceipts = append(pushReceipts, receipt)
	}

	auth.resp(w, pushReceipts)
}
