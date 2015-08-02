# shadowfax
[![Build Status](https://travis-ci.org/cmars/shadowfax.svg)](https://travis-ci.org/cmars/shadowfax)
[![GoDoc](https://godoc.org/github.com/cmars/shadowfax?status.svg)](https://godoc.org/github.com/cmars/shadowfax)

Shadowfax is a simple, lightweight confidential messaging system. It should be
considered an experimental tech preview. Shadowfax hasn't been battle-tested,
security-reviewed or deployed into production.

Shadowfax clients are identified by their 32-byte curve25519 public key. Clients
address messages to each other confidentially using authenticated public key
encryption.

Messages are exchanged through routers, to which the content between sender and
receiver is opaque -- only the sender and receiver public keys are disclosed.
Currently HTTP is supported, but other transports may be added. Additional
layers of security may be provided by the network protocol, but the underlying
confidentiality of shadowfax messages does not rely upon it.

# License

Copyright 2015 Casey Marshall.

This Source Code Form is subject to the terms of the [Mozilla Public License, v. 2.0](LICENSE).
If a copy of the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.

