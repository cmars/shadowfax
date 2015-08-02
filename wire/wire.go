/*
  Copyright 2015 Casey Marshall.

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

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
