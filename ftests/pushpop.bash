#!/bin/bash -ex

go build -o sfd github.com/cmars/shadowfax/cmd/sfd
go build -o sf github.com/cmars/shadowfax/cmd/sf

rm -rf .alice .bob

./sfd &
SFD_PID=$!
trap "kill ${SFD_PID}" EXIT
sleep 1

SFD_KEY=$(basen -encode 58 <(head -c 32 sfd.keypair))
if [ -z "$SFD_KEY" ]; then
	echo "failed to read server key"
	exit 1
fi


./sf --homedir .alice --passphrase /dev/null addr create
ALICE_ADDR=$(./sf --homedir .alice --passphrase /dev/null addr default)
if [ -z "$ALICE_ADDR" ]; then
	echo "failed to read alice address"
	exit 1
fi

# Bob creates an address
./sf --homedir .bob --passphrase /dev/null addr create
BOB_ADDR=$(./sf --homedir .bob --passphrase /dev/null addr default)
if [ -z "$BOB_ADDR" ]; then
	echo "failed to read bob address"
	exit 1
fi

# Exchange addresses
./sf --homedir .alice name add bob $BOB_ADDR
./sf --homedir .bob name add alice $ALICE_ADDR

# Alice sends Bob a message
ALICE_MSG=$(mktemp)
trap "rm -f $ALICE_MSG" EXIT
echo "hello" > $ALICE_MSG
./sf --server-key ${SFD_KEY} --url http://localhost:8080 --homedir .alice --passphrase /dev/null msg push bob $ALICE_MSG

# Bob checks messages
./sf --server-key ${SFD_KEY} --url http://localhost:8080 --homedir .bob --passphrase /dev/null msg pop

