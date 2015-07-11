package storage

type Service interface {
	Push(msg *AddressedMessage) error
	Pop(recipient string) ([]*AddressedMessage, error)
}

type Message struct {
	ID       string
	Contents []byte
}

type AddressedMessage struct {
	Message
	Recipient string
	Sender    string
}
