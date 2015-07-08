package wire

type Error struct {
	Code    int    `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
	OK      bool   `json:"ok"`
}

type PublicKeyResponse struct {
	PublicKey string `json:"public-key"`
}

type Message struct {
	ID       string `json:"id"`
	Contents []byte `json:"contents"`
}

type PushMessage struct {
	Message
	Recipient string `json:"recipient,omitempty"`
}

type PopMessage struct {
	Message
	Sender string `json:"sender,omitempty"`
}

type PushReceipt struct {
	ID string `json:"id"`
	OK bool   `json:"ok"`
}
