#!/bin/bash -ex
#
#  Copyright 2015 Casey Marshall.
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at http://mozilla.org/MPL/2.0/.
#

if [ ! -d "$GOPATH" ]; then
	echo "GOPATH not found"
	exit 1
fi

for x in sf sfd basen; do
	if [ ! -x "$GOPATH/bin/$x" ]; then
		echo "missing binary: $x"
		exit 1
	fi
done

TESTDIR=$(mktemp -d)
TRAPEXIT="rm -rf $TESTDIR"
trap "$TRAPEXIT" EXIT
cd $TESTDIR

$GOPATH/bin/sfd &
SFD_PID=$!
TRAPEXIT="$TRAPEXIT;kill ${SFD_PID}"  # shitty bash defer
trap "$TRAPEXIT" EXIT
sleep 1

SFD_KEY=$($GOPATH/bin/basen -encode 58 <(head -c 32 sfd.keypair))
if [ -z "$SFD_KEY" ]; then
	echo "failed to read server key"
	exit 1
fi


$GOPATH/bin/sf --homedir .alice --passphrase /dev/null addr create
ALICE_ADDR=$($GOPATH/bin/sf --homedir .alice --passphrase /dev/null addr default)
if [ -z "$ALICE_ADDR" ]; then
	echo "failed to read alice address"
	exit 1
fi

# Bob creates an address
$GOPATH/bin/sf --homedir .bob --passphrase /dev/null addr create
BOB_ADDR=$($GOPATH/bin/sf --homedir .bob --passphrase /dev/null addr default)
if [ -z "$BOB_ADDR" ]; then
	echo "failed to read bob address"
	exit 1
fi

# Exchange addresses
$GOPATH/bin/sf --homedir .alice name add bob $BOB_ADDR
$GOPATH/bin/sf --homedir .bob name add alice $ALICE_ADDR

# Alice sends Bob a message
ALICE_MSG=$(mktemp)
TRAPEXIT="$TRAPEXIT;rm -f $ALICE_MSG"
trap "$TRAPEXIT" EXIT
echo "hello" > $ALICE_MSG
$GOPATH/bin/sf --server-key ${SFD_KEY} --url http://localhost:8080 --homedir .alice --passphrase /dev/null msg push bob $ALICE_MSG

# Bob checks messages
$GOPATH/bin/sf --server-key ${SFD_KEY} --url http://localhost:8080 --homedir .bob --passphrase /dev/null msg pop

