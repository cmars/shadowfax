#!/bin/bash -ex

TESTDIR=$(mktemp -d)
TRAPEXIT="rm -rf $TESTDIR"
trap "$TRAPEXIT" EXIT
cd $TESTDIR

mkdir bin

go build -o bin/sfd github.com/cmars/shadowfax/cmd/sfd
go build -o bin/sf github.com/cmars/shadowfax/cmd/sf

if [ ! -x bin/basen ]; then
	go build -o bin/basen gopkg.in/basen.v1/cmd/basen
fi

bin/sfd &
SFD_PID=$!
TRAPEXIT="$TRAPEXIT;kill ${SFD_PID}"  # shitty bash defer
trap "$TRAPEXIT" EXIT
sleep 1

SFD_KEY=$(bin/basen -encode 58 <(head -c 32 sfd.keypair))
if [ -z "$SFD_KEY" ]; then
	echo "failed to read server key"
	exit 1
fi


bin/sf --homedir .alice --passphrase /dev/null addr create
ALICE_ADDR=$(bin/sf --homedir .alice --passphrase /dev/null addr default)
if [ -z "$ALICE_ADDR" ]; then
	echo "failed to read alice address"
	exit 1
fi

# Bob creates an address
bin/sf --homedir .bob --passphrase /dev/null addr create
BOB_ADDR=$(bin/sf --homedir .bob --passphrase /dev/null addr default)
if [ -z "$BOB_ADDR" ]; then
	echo "failed to read bob address"
	exit 1
fi

# Exchange addresses
bin/sf --homedir .alice name add bob $BOB_ADDR
bin/sf --homedir .bob name add alice $ALICE_ADDR

# Alice sends Bob a message
ALICE_MSG=$(mktemp)
TRAPEXIT="$TRAPEXIT;rm -f $ALICE_MSG"
trap "$TRAPEXIT" EXIT
echo "hello" > $ALICE_MSG
bin/sf --server-key ${SFD_KEY} --url http://localhost:8080 --homedir .alice --passphrase /dev/null msg push bob $ALICE_MSG

# Bob checks messages
bin/sf --server-key ${SFD_KEY} --url http://localhost:8080 --homedir .bob --passphrase /dev/null msg pop

