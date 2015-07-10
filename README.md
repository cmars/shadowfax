# shadowfax

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

